from os import getenv

import logging

from dotenv import load_dotenv

import nextcord
from nextcord.ext import commands

from passlib.hash import bcrypt_sha256
# import pymysql  # ctfd db를 불러오므로 ORM을 사용하지 않음
import sqlalchemy


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

    async def etc(self, msg):
        await self.channel.send(msg)


class User():
    def __init__(self, conn, engine):
        self.conn = conn
        self.engine = engine
        self.user_table, self.auth_table = self.load_tables()

    def load_tables(self):
        user_table = sqlalchemy.Table(
            'users', sqlalchemy.MetaData(), autoload=True, autoload_with=self.engine)
        auth_table = sqlalchemy.Table(
            'auth', sqlalchemy.MetaData(), autoload=True, autoload_with=self.engine)
        return user_table, auth_table

    def select_query(self, query):
        res = self.conn.execute(query)
        data = res.fetchone()

        return data

    def get_ctfd_user_info_by_email(self, email):
        query = sqlalchemy.select([self.user_table.c.id, self.user_table.c.password]).where(
            self.user_table.c.email == email)
        return self.select_query(query)

    def get_discord_user_by_discord_id(self, discord_id):
        query = sqlalchemy.select([self.auth_table]).where(
            self.auth_table.c.discord_id == discord_id)
        return self.select_query(query)

    def create_discord_user(self, discord_id) -> bool:
        query = self.auth_table.insert().values(discord_id=discord_id)

        try:
            self.conn.execute(query)
        except sqlalchemy.exc.IntegrityError:
            return False

        return True

    def connect_discord_user_with_ctfd_user(self, discord_id, ctfd_id) -> bool:
        discord_user = self.get_discord_user_by_discord_id(discord_id)

        if discord_user is None:
            return False

        query = self.auth_table.update().where(self.auth_table.c.discord_id ==
                                               discord_id).values(ctfd_id=ctfd_id)

        try:
            self.conn.execute(query)
        except sqlalchemy.exc.IntegrityError:
            return False

        return True

    def check_ctfd_user_is_connected(self, ctfd_id) -> bool:
        query = self.auth_table.select().where(
            self.auth_table.c.ctfd_id == ctfd_id)
        if self.select_query(query) is None:
            return False
        return True

    def increase_login_try(self, discord_id) -> bool:
        query = self.auth_table.select().where(
            self.auth_table.c.discord_id == discord_id)
        discord_user = self.select_query(query)

        if discord_user is None:
            return False

        query = self.auth_table.update().where(self.auth_table.c.discord_id == discord_id).values(
            login_try=discord_user["login_try"] + 1)
        try:
            self.conn.execute(query)
        except sqlalchemy.exc.IntegrityError:
            return False

        return True

    def get_ctfd_user_name_by_id(self, ctfd_id):
        query = sqlalchemy.select([self.user_table.c.name]).where(
            self.user_table.c.id == ctfd_id)
        return self.select_query(query)


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

    async def set_permissions(self, interaction, discord_id, ctfd_id):
        username = users.get_ctfd_user_name_by_id(ctfd_id)

        if username is None:
            await interaction.response.send_message("예기치 못한 오류", ephemeral=True)
            await log.error("set_permissions", [interaction, discord_id, ctfd_id], {})
            return
        # try:
        #     await interaction.user.edit(nick=username[0])
        #     await interaction.user.remove_roles(interaction.user.guild.get_role(AUTH_ROLE_ID))
        # except nextcord.errors.Forbidden:
            # await interaction.response.send_message("봇보다 높은 권한을 가진 유저는 해당 명령을 실행할 수 없습니다.", ephemeral=True)
            # return

        await interaction.response.send_message("이미 인증되었습니다.", ephemeral=True)
        await log.etc(f"<@{interaction.user.id}>님이 재인증을 시도하였습니다.")

    async def link_and_set_permissions(self, interaction, discord_id, ctfd_id):
        if not users.connect_discord_user_with_ctfd_user(discord_id, ctfd_id):
            await interaction.response.send_message("예기치 못한 오류", ephemeral=True)
            await log.error("set_permissions", [interaction, discord_id, ctfd_id], {})
            return

        return await self.set_permissions(interaction, discord_id, ctfd_id)

    async def callback(self, interaction: nextcord.Interaction) -> None:
        discord_user_info = users.get_discord_user_by_discord_id(
            interaction.user.id)

        if discord_user_info is None:
            users.create_discord_user(interaction.user.id)
            discord_user_info = users.get_discord_user_by_discord_id(
                interaction.user.id)

        if discord_user_info['login_try'] >= 5:
            await interaction.response.send_message("인증 시도 횟수가 5회를 초과하여 인증 기능이 잠겼습니다.\n운영진에게 문의하세요.", ephemeral=True)
            await log.lock(interaction.user.id, self.email.value)
            return

        user_info = users.get_ctfd_user_info_by_email(self.email.value)

        try:
            if user_info is None:
                raise InvalidLoginInfo
            if discord_user_info['ctfd_id'] is not None:
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
            else:
                await interaction.response.send_message("예기치 못한 오류", ephemeral=True)
                sys_logger.error(reason)
            return

        await self.link_and_set_permissions(interaction, interaction.user.id, user_info['id'])


class Login(nextcord.ui.View):
    def __init__(self):
        super().__init__()

    @nextcord.ui.button(label="로그인", style=nextcord.ButtonStyle.green)
    async def login(self, button: nextcord.ui.Button, interaction: nextcord.Interaction):
        modal = Auth()
        discord_user_info = users.get_discord_user_by_discord_id(
            interaction.user.id)
        if discord_user_info['ctfd_id'] is not None:
            await modal.set_permissions(interaction, interaction.user.id, discord_user_info['ctfd_id'])
            return

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


async def connect_db(db_url: str):
    engine = sqlalchemy.create_engine(db_url)
    conn = engine.connect()

    query = sqlalchemy.select([sqlalchemy.func.count()]).select_from(sqlalchemy.text(
        "information_schema.tables")).where(sqlalchemy.text("TABLE_NAME = 'auth'"))
    res = conn.execute(query)
    data = res.fetchone()

    if data[0] != 1:
        meta = sqlalchemy.MetaData()
        sqlalchemy.Table('users', meta, autoload=True, autoload_with=engine)
        auth_table = sqlalchemy.Table(
            'auth', meta,
            sqlalchemy.Column('id', sqlalchemy.Integer,
                              primary_key=True, autoincrement=True, nullable=False),
            sqlalchemy.Column('discord_id', sqlalchemy.BigInteger,
                              nullable=False, unique=True),
            sqlalchemy.Column('ctfd_id', sqlalchemy.Integer, sqlalchemy.ForeignKey(
                'users.id', ondelete="CASCADE"), nullable=True, unique=True),
            sqlalchemy.Column('login_try', sqlalchemy.Integer,
                              nullable=False, server_default="0"),
        )
        meta.create_all(engine)

        sys_logger.info("AUTH TABLE Created")
        return conn, engine
    else:
        expected_columns = {
            'id': {'COLUMN_TYPE': 'int', 'COLUMN_DEFAULT': None, 'IS_NULLABLE': 'NO', 'COLUMN_KEY': 'PRI', 'EXTRA': 'auto_increment'},
            'discord_id': {'COLUMN_TYPE': 'bigint', 'COLUMN_DEFAULT': None, 'IS_NULLABLE': 'NO', 'COLUMN_KEY': 'UNI', 'EXTRA': ''},
            'ctfd_id': {'COLUMN_TYPE': 'int', 'COLUMN_DEFAULT': None, 'IS_NULLABLE': 'YES', 'COLUMN_KEY': 'UNI', 'EXTRA': ''},
            'login_try': {'COLUMN_TYPE': 'int', 'COLUMN_DEFAULT': '0', 'IS_NULLABLE': 'NO', 'COLUMN_KEY': '', 'EXTRA': ''}
        }

        query = sqlalchemy.select([sqlalchemy.text("COLUMN_NAME, COLUMN_TYPE, COLUMN_DEFAULT, IS_NULLABLE, COLUMN_KEY, EXTRA")]).select_from(sqlalchemy.text(
            "information_schema.columns")).where(sqlalchemy.text("TABLE_NAME = 'auth'"))
        res = conn.execute(query)
        data = res.fetchall()

        if len(data) != len(expected_columns):
            pass
        else:
            for i, col in enumerate(data):
                expected = expected_columns.get(col['COLUMN_NAME'])
                if not expected or any([col[k] != v for k, v in expected.items()]):
                    break
                elif i == len(data) - 1:
                    sys_logger.info("DB Connected")
                    return conn, engine
        sys_logger.warning(
            "DB validation failed.\nWe will drop the table and re-create it.\nAll data will be lost.")

        if await bot.loop.run_in_executor(None, input, 'Continue? (y/n):').lower() != 'y':
            sys_logger.info('Abort.')
            await bot.close()

        query = sqlalchemy.text("DROP TABLE auth;")
        conn.execute(query)
        return await connect_db(db_url)


async def check_env():
    env_vars = ['SERVER_ID', 'AUTH_CHANNEL_ID',
                'AUTH_ROLE_ID', 'LOG_CHANNEL_ID', 'DB_URL']

    for env in env_vars:
        if not getenv(env):
            sys_logger.error('%s is not set.', env)
            await bot.close()

    if not bot.get_channel(AUTH_CHANNEL_ID):
        sys_logger.error('AUTH_CHANNEL_ID is invalid.')
        await bot.close()

    if not bot.get_channel(LOG_CHANNEL_ID):
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

    conn, engine = await connect_db(getenv('DB_URL'))
    users = User(conn=conn, engine=engine)

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
    elif user["ctfd_id"] is not None:
        return
    await member.add_roles(bot.get_guild(SERVER_ID).get_role(AUTH_ROLE_ID))


@ bot.event
async def on_error(event, *args, **kwargs):
    sys_logger.error('Ignoring exception in %s', event, exc_info=True)
    await log.error(event, args, kwargs)

bot.run(getenv('BOT_TOKEN'))
