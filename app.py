from os import getenv

from dotenv import load_dotenv

import nextcord
from nextcord.ext import commands

from passlib.hash import bcrypt_sha256
import pymysql  # ctfd db를 불러오므로 ORM을 사용하지 않음

load_dotenv()

SERVER_ID = int(getenv('SERVER_ID'))
AUTH_CHANNEL_ID = int(getenv('AUTH_CHANNEL_ID'))
AUTH_ROLE_ID = int(getenv('AUTH_ROLE_ID'))
LOG_CHANNEL_ID = int(getenv('LOG_CHANNEL_ID'))

# TODO : 인증 로그 구현
#      : 입력 시도 제한


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
        self.cursor.execute(
            f"SELECT id, password, name FROM users WHERE email='{email}'")
        self.db.commit()

        found = self.cursor.fetchone()
        if found == None:
            return None

        return found

    def get_discord_user_by_discord_id(self, discord_id):
        self.cursor.execute(
            f"SELECT * FROM auth WHERE discord_id='{discord_id}'")
        self.db.commit()

        found = self.cursor.fetchone()
        if found == None:
            return None

        return found

    def create_discord_user(self, discord_id) -> bool:
        self.cursor.execute(
            f"INSERT INTO auth (discord_id) VALUES ('{discord_id}')")
        self.db.commit()

        return True

    def connect_discord_user_with_ctfd_user(self, discord_id, user_id) -> bool:
        discord_user = self.get_discord_user_by_discord_id(discord_id)

        if discord_user is None:
            return False

        self.cursor.execute(
            f"UPDATE auth SET user_id='{user_id}' WHERE discord_id='{discord_id}'")
        self.db.commit()

        return True

    def check_ctfd_user_is_connected(self, user_id) -> bool:
        self.cursor.execute(
            f"SELECT * FROM auth WHERE user_id='{user_id}'")
        self.db.commit()

        found = self.cursor.fetchone()
        if found == None:
            return False

        return True

    def increase_login_try(self, discord_id) -> bool:
        self.cursor.execute(
            f"UPDATE auth SET try=try+1 WHERE discord_id='{discord_id}'")
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

        print(discord_user_info)

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

        try:
            await interaction.user.edit(nick=user_info['name'])
            await interaction.user.remove_roles(interaction.user.guild.get_role(AUTH_ROLE_ID))
        except nextcord.errors.Forbidden:
            await interaction.response.send_message("봇보다 높은 권한을 가진 유저는 해당 명령을 실행할 수 없습니다.", ephemeral=True)
            return

        if users.connect_discord_user_with_ctfd_user(interaction.user.id, user_info['id']):
            await interaction.response.send_message("인증되었습니다.", ephemeral=True)
            await log.success(interaction.user.id, self.email.value)
        else:
            await interaction.response.send_message("예기치 못한 오류", ephemeral=True)


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
    await auth_channel.set_permissions(bot.get_guild(SERVER_ID).get_role(AUTH_ROLE_ID), view_channel=True)
    await auth_channel.set_permissions(bot.get_guild(SERVER_ID).default_role, view_channel=False)
    await auth_channel.set_permissions(bot.get_guild(SERVER_ID).default_role, send_messages=False)

    for channel in bot.get_all_channels():
        if channel.id != auth_channel.id:
            await channel.set_permissions(bot.get_guild(SERVER_ID).get_role(AUTH_ROLE_ID), view_channel=False)


def connect_db() -> pymysql.cursors.Cursor:
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

        print('DB Created')
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
            print('DB Connected')
            return cursor

        print('DB validation failed.')
        print('We will drop the table and re-create it.')
        print('All data will be lost.')

        if input('Continue? (y/n): ') != 'y':
            print('Abort.')
            exit(1)

        cursor.execute("DROP TABLE auth;")
        db.close()
        return connect_db()  # expect to return cursor


async def initialize():
    global log, users

    await bot.wait_until_ready()

    log = logger(LOG_CHANNEL_ID)

    cursor = connect_db()
    users = User(db, cursor)

    auth_channel = bot.get_channel(AUTH_CHANNEL_ID)
    await set_channel_perm(auth_channel)

    view = Login()

    await auth_channel.purge()
    await auth_channel.send("대회 사이트 계정으로 로그인 해주세요.", view=view)


@ bot.event
async def on_ready():
    await initialize()
    print("Bot is ready.")


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
    await log.error(event, args, kwargs)

bot.run(getenv('BOT_TOKEN'))
