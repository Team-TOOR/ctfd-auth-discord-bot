from os import getenv

import logging

from dotenv import load_dotenv

import nextcord
from nextcord.ext import commands

from passlib.hash import bcrypt_sha256
import pymysql  # ctfd db를 불러오므로 ORM을 사용하지 않음


sys_logger = logging.getLogger('nextcord')
sys_logger.setLevel(logging.INFO)

file_handler = logging.FileHandler(
    filename='bot.log', encoding='utf-8', mode='w')
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s:%(levelname)s:%(name)s: %(message)s'))
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(logging.Formatter(
    '%(asctime)s:%(levelname)s:%(name)s: %(message)s'))

sys_logger.addHandler(file_handler)
sys_logger.addHandler(stream_handler)

load_dotenv()

SERVER_ID = int(getenv('SERVER_ID'))
AUTH_CHANNEL_ID = int(getenv('AUTH_CHANNEL_ID'))
AUTH_ROLE_ID = int(getenv('AUTH_ROLE_ID'))
LOG_CHANNEL_ID = int(getenv('LOG_CHANNEL_ID'))


class InvalidLoginInfo(Exception):
    def __init__(self):
        super().__init__('올바르지 않은 로그인 정보')


class AlreadyUsedLoginInfo(Exception):
    def __init__(self):
        super().__init__('이미 사용중인 로그인 정보')


class logger():
    def __init__(self, channel_id):
        self.channel = bot.get_channel(channel_id)

    async def success(self, user_id, email):
        await self.channel.send(f'<@{user_id}>님이 `{email}` 계정 인증에 성공하였습니다.')

    async def fail(self, user_id, email):
        await self.channel.send(f'<@{user_id}>님이 `{email}` 계정 인증에 실패하였습니다.')

    async def lock(self, user_id, email):
        await self.channel.send(
            f'<@{user_id}>님이 `{email}` 계정 인증에 5회 실패하여 인증 기능이 잠겼습니다.')

    async def error(self, event, args, kwargs):
        await self.channel.send(
            f'`{event}` 이벤트에서 에러가 발생하였습니다.\n\n`{args}`\n`{kwargs}`')


class User():
    def __init__(self, conn, cursor):
        self.db = conn
        self.cursor = cursor

    def get_ctfd_user_info_by_email(self, email):
        sql = "SELECT id, password, name FROM users WHERE email=%s"
        self.cursor.execute(sql, (email,))
        self.db.commit()

        found = self.cursor.fetchone()
        if found == None:
            return None

        return found

    def get_discord_user_by_discord_id(self, discord_id):
        sql = "SELECT * FROM auth WHERE discord_id=%s"
        self.cursor.execute(sql, (discord_id,))
        self.db.commit()

        found = self.cursor.fetchone()
        if found == None:
            return None

        return found

    def create_discord_user(self, discord_id) -> bool:
        sql = "INSERT INTO auth (discord_id) VALUES (%s)"
        self.cursor.execute(sql, (discord_id,))
        self.db.commit()

        return True

    def connect_discord_user_with_ctfd_user(self, discord_id, user_id) -> bool:
        discord_user = self.get_discord_user_by_discord_id(discord_id)

        if discord_user is None:
            return False

        sql = "UPDATE auth SET user_id=%s WHERE discord_id=%s"
        self.cursor.execute(sql, (user_id, discord_id))
        self.db.commit()

        return True

    def check_ctfd_user_is_connected(self, user_id) -> bool:
        sql = "SELECT * FROM auth WHERE user_id=%s"
        self.cursor.execute(sql, (user_id,))
        self.db.commit()

        found = self.cursor.fetchone()
        if found == None:
            return False

        return True

    def increase_login_try(self, discord_id) -> bool:
        sql = "UPDATE auth SET try=try+1 WHERE discord_id=%s"
        self.cursor.execute(sql, (discord_id,))
        self.db.commit()

        return True


class Auth(nextcord.ui.Modal):
    def __init__(self):
        super().__init__(
            "로그인",
            timeout=1 * 60,  # 1 minutes
        )

        self.email = nextcord.ui.TextInput(
            custom_id="email",
            label="이메일",
            placeholder="대회 사이트 이메일",
            min_length=2,
            max_length=30,
        )
        self.add_item(self.email)

        self.password = nextcord.ui.TextInput(
            custom_id="password",
            label="비밀번호",
            placeholder="대회 사이트 비밀번호",
            min_length=2,
            max_length=30,
        )
        self.add_item(self.password)

    def verify_password(self, plaintext, ciphertext) -> bool:
        return bcrypt_sha256.verify(plaintext, ciphertext)

    async def callback(self, interaction: nextcord.Interaction) -> None:
        discord_user_info = users.get_discord_user_by_discord_id(
            interaction.user.id)

        if discord_user_info is None:
            users.create_discord_user(interaction.user.id)
            discord_user_info = users.get_discord_user_by_discord_id(
                interaction.user.id)

        if discord_user_info['try'] >= 5:
            await interaction.response.send_message("인증 시도 횟수가 5회를 초과하여 인증 기능이 잠겼습니다.\n운영진에게 문의하세요.", ephemeral=True)
            await log.lock(interaction.user.id, self.email.value)
            return

        user_info = users.get_ctfd_user_info_by_email(self.email.value)

        try:
            if user_info is None:
                raise InvalidLoginInfo
            if discord_user_info['user_id'] is not None:
                raise AlreadyUsedLoginInfo
            if users.check_ctfd_user_is_connected(user_info['id']):
                raise AlreadyUsedLoginInfo
            if not self.verify_password(self.password.value, user_info['password']):
                raise InvalidLoginInfo
        except Exception as reason:
            users.increase_login_try(interaction.user.id)
            await log.fail(interaction.user.id, self.email.value)

            if isinstance(reason, InvalidLoginInfo):
                await interaction.response.send_message("올바르지 않은 이메일 또는 비밀번호입니다.", ephemeral=True)
            elif isinstance(reason, AlreadyUsedLoginInfo):
                await interaction.response.send_message("이미 사용중인 이메일입니다.", ephemeral=True)
            return

        if not users.connect_discord_user_with_ctfd_user(interaction.user.id, user_info['id']):
            await interaction.response.send_message("예기치 못한 오류", ephemeral=True)
            return

        try:
            await interaction.user.edit(nick=user_info['name'])
            await interaction.user.remove_roles(interaction.user.guild.get_role(AUTH_ROLE_ID))
        except nextcord.errors.Forbidden:
            await interaction.response.send_message("봇보다 높은 권한을 가진 유저는 해당 명령을 실행할 수 없습니다.", ephemeral=True)
            return

        await interaction.response.send_message("인증되었습니다.", ephemeral=True)
        await log.success(interaction.user.id, self.email.value)


class Login(nextcord.ui.View):
    def __init__(self):
        super().__init__()

    @nextcord.ui.button(label="로그인", style=nextcord.ButtonStyle.green)
    async def login(self, button: nextcord.ui.Button, interaction: nextcord.Interaction):
        modal = Auth()
        await interaction.response.send_modal(modal)


intents = nextcord.Intents.all()

bot = commands.Bot(intents=intents)


async def set_channel_perm(auth_channel: nextcord.TextChannel):
    default = auth_channel.overwrites_for(
        bot.get_guild(SERVER_ID).default_role)
    default.view_channel = False
    default.read_messages = False
    default.read_message_history = False
    default.send_messages = False
    await auth_channel.set_permissions(target=bot.get_guild(SERVER_ID).default_role, overwrite=default, reason="인증 채널 생성")

    auth = auth_channel.overwrites_for(
        bot.get_guild(SERVER_ID).get_role(AUTH_ROLE_ID))
    auth.view_channel = True
    auth.read_messages = True
    auth.read_message_history = True
    auth.send_messages = False
    await auth_channel.set_permissions(target=bot.get_guild(SERVER_ID).get_role(AUTH_ROLE_ID), overwrite=auth, reason="인증 채널 생성")

    for channel in bot.get_all_channels():
        if channel.id != AUTH_CHANNEL_ID:
            auth = channel.overwrites_for(
                bot.get_guild(SERVER_ID).get_role(AUTH_ROLE_ID))
            auth.view_channel = False
            auth.read_messages = False
            auth.read_message_history = False
            auth.send_messages = False
            await channel.set_permissions(target=bot.get_guild(SERVER_ID).get_role(AUTH_ROLE_ID), overwrite=auth, reason="인증 채널 생성")


async def connect_db() -> pymysql.cursors.Cursor:
    global db

    db = pymysql.connect(host=getenv('DB_HOST'),
                         port=int(getenv('DB_PORT')),
                         user=getenv('DB_USER'),
                         passwd=getenv('DB_PASSWORD'),
                         db=getenv('DB_NAME'),
                         cursorclass=pymysql.cursors.DictCursor)
    cursor = db.cursor()

    cursor.execute(
        "SELECT COUNT(*) FROM information_schema.tables WHERE TABLE_NAME = 'auth';")
    if cursor.fetchone()['COUNT(*)'] != 1:
        cursor.execute(
            "CREATE TABLE auth (id INT(11) NOT NULL AUTO_INCREMENT PRIMARY KEY, discord_id BIGINT(20) NOT NULL UNIQUE, user_id INT(11) UNIQUE, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE, try INT(11) NOT NULL DEFAULT 0);")
        db.commit()

        sys_logger.info('DB Created')
        return cursor
    else:
        cursor.execute(
            "SELECT COLUMN_NAME, COLUMN_TYPE, COLUMN_DEFAULT, IS_NULLABLE, COLUMN_KEY, EXTRA FROM information_schema.columns WHERE TABLE_NAME = 'auth';")

        found = cursor.fetchall()
        if len(found) != 4:
            pass
        elif found[0]['COLUMN_NAME'] != 'id' or found[0]['COLUMN_TYPE'] != 'int' or found[0]['COLUMN_DEFAULT'] != None or found[0]['IS_NULLABLE'] != 'NO' or found[0]['COLUMN_KEY'] != 'PRI' or found[0]['EXTRA'] != 'auto_increment':
            pass
        elif found[1]['COLUMN_NAME'] != 'discord_id' or found[1]['COLUMN_TYPE'] != 'bigint' or found[1]['COLUMN_DEFAULT'] != None or found[1]['IS_NULLABLE'] != 'NO' or found[1]['COLUMN_KEY'] != 'UNI' or found[1]['EXTRA'] != '':
            pass
        elif found[2]['COLUMN_NAME'] != 'user_id' or found[2]['COLUMN_TYPE'] != 'int' or found[2]['COLUMN_DEFAULT'] != None or found[2]['IS_NULLABLE'] != 'YES' or found[2]['COLUMN_KEY'] != 'UNI' or found[2]['EXTRA'] != '':
            pass
        elif found[3]['COLUMN_NAME'] != 'try' or found[3]['COLUMN_TYPE'] != 'int' or found[3]['COLUMN_DEFAULT'] != '0' or found[3]['IS_NULLABLE'] != 'NO' or found[3]['COLUMN_KEY'] != '' or found[3]['EXTRA'] != '':
            pass
        else:
            sys_logger.info('DB Connected')
            return cursor

        sys_logger.warn(
            'DB validation failed.\nWe will drop the table and re-create it.\nAll data will be lost.')

        if input('Continue? (y/n): ') != 'y':
            sys_logger.info('Abort.')
            await bot.close()

        cursor.execute("DROP TABLE auth;")
        db.close()
        return await connect_db()  # expect to return cursor


async def check_env():
    if not getenv('SERVER_ID'):
        sys_logger.error('SERVER_ID is not set.')
        await bot.close()

    if not getenv('AUTH_CHANNEL_ID'):
        sys_logger.error('AUTH_CHANNEL_ID is not set.')
        await bot.close()

    if not getenv('AUTH_ROLE_ID'):
        sys_logger.error('AUTH_ROLE_ID is not set.')
        await bot.close()

    if not getenv('LOG_CHANNEL_ID'):
        sys_logger.error('LOG_CHANNEL_ID is not set.')
        await bot.close()

    if not getenv('DB_HOST'):
        sys_logger.error('DB_HOST is not set.')
        await bot.close()

    if not getenv('DB_PORT'):
        sys_logger.error('DB_PORT is not set.')
        await bot.close()

    if not getenv('DB_USER'):
        sys_logger.error('DB_USER is not set.')
        await bot.close()

    if not getenv('DB_PASSWORD'):
        sys_logger.error('DB_PASSWORD is not set.')
        await bot.close()

    if not getenv('DB_NAME'):
        sys_logger.error('DB_NAME is not set.')
        await bot.close()

    channel = bot.get_channel(AUTH_CHANNEL_ID)
    if not channel:
        sys_logger.error('AUTH_CHANNEL_ID is invalid.')
        await bot.close()

    channel = bot.get_channel(LOG_CHANNEL_ID)
    if not channel:
        sys_logger.error('LOG_CHANNEL_ID is invalid.')
        await bot.close()

    guild = bot.get_guild(SERVER_ID)
    if not guild:
        sys_logger.error('SERVER_ID is invalid.')
        await bot.close()

    if not guild.get_role(AUTH_ROLE_ID):
        sys_logger.error('AUTH_ROLE_ID is invalid.')
        await bot.close()


async def initialize():
    global log, users

    await bot.wait_until_ready()

    await check_env()

    log = logger(LOG_CHANNEL_ID)

    cursor = await connect_db()
    users = User(db, cursor)

    auth_channel = bot.get_channel(AUTH_CHANNEL_ID)
    await set_channel_perm(auth_channel)

    view = Login()

    await auth_channel.purge()
    await auth_channel.send("대회 사이트 계정으로 로그인 해주세요.", view=view)


@ bot.event
async def on_ready():
    await initialize()
    sys_logger.info("Bot is ready.")


@ bot.event
async def on_member_join(member: nextcord.Member):
    user = users.get_discord_user_by_discord_id(member.id)
    if user is None:
        users.create_discord_user(member.id)
    elif user["user_id"] is not None:
        return
    await member.add_roles(bot.get_guild(SERVER_ID).get_role(AUTH_ROLE_ID))


@ bot.event
async def on_error(event, *args, **kwargs):
    sys_logger.error('Ignoring exception in %s', event, exc_info=True)
    await log.error(event, args, kwargs)

bot.run(getenv('BOT_TOKEN'))
