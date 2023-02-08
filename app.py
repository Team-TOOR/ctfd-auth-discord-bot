from os import getenv

from dotenv import load_dotenv

import nextcord
from nextcord.ext import commands

from passlib.hash import bcrypt_sha256
import pymysql

load_dotenv()

SERVER_ID = int(getenv('SERVER_ID'))
AUTH_CHANNEL_ID = int(getenv('AUTH_CHANNEL_ID'))
AUTH_ROLE_ID = int(getenv('AUTH_ROLE_ID'))
LOG_CHANNEL_ID = int(getenv('LOG_CHANNEL_ID'))

# TODO : 인증 로그 구현
#      : 입력 시도 제한
#      : env 생성


class logger():
    def __init__(self, channel_id):
        self.channel = bot.get_channel(channel_id)

    async def success(self, user_id, email):
        await self.channel.send(f'<@{user_id}>님이 `{email}` 계정 인증에 성공하였습니다.')

    async def fail(self, user_id, email):
        await self.channel.send(
            f'<@{user_id}>님이 `{email}` 계정 인증에 5회 실패하여 인증 기능이 잠겼습니다.')

    async def error(self, event, args, kwargs):
        await self.channel.send(
            f'`{event}` 이벤트에서 에러가 발생하였습니다.\n\n`{args}`\n`{kwargs}`')


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

    def verify_password(self, plaintext, ciphertext):
        return bcrypt_sha256.verify(plaintext, ciphertext)

    def get_user_info_by_email(self, email):
        cursor.execute(
            f"SELECT password, name FROM users WHERE email='{email}'")

        found = cursor.fetchone()
        if found == None:
            return None

        return found

    async def callback(self, interaction: nextcord.Interaction) -> None:
        user_info = self.get_user_info_by_email(self.email.value)
        if user_info == None or self.verify_password(self.password.value, user_info[0]) == False:
            await interaction.response.send_message("이메일 또는 비밀번호가 일치하지 않습니다.", ephemeral=True)
            return

        try:
            await interaction.user.edit(nick=user_info[1])
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
    await auth_channel.set_permissions(bot.get_guild(SERVER_ID).default_role, view_channel=True)
    await auth_channel.set_permissions(bot.get_guild(SERVER_ID).default_role, send_messages=False)

    for channel in bot.get_all_channels():
        if channel.id == auth_channel.id:
            await channel.set_permissions(bot.get_guild(SERVER_ID).get_role(AUTH_ROLE_ID), view_channel=True)
            continue
        await channel.set_permissions(bot.get_guild(SERVER_ID).get_role(AUTH_ROLE_ID), view_channel=False)


def connect_db():
    global db, cursor

    db = pymysql.connect(host=getenv('DB_HOST'),
                         port=int(getenv('DB_PORT')),
                         user=getenv('DB_USER'),
                         passwd=getenv('DB_PASSWORD'),
                         db=getenv('DB_NAME'))
    cursor = db.cursor()

    cursor.execute(
        "SELECT COUNT(*) FROM information_schema.tables WHERE TABLE_NAME = 'auth';")
    if cursor.fetchone()[0] != 1:
        cursor.execute(
            "CREATE TABLE auth (id BIGINT(20), try INT(11) NOT NULL DEFAULT 0, pass TINYINT(1) NOT NULL DEFAULT 0);")
        db.commit()

        print('DB Created')
    else:
        cursor.execute(
            "SELECT COLUMN_NAME, COLUMN_TYPE, COLUMN_DEFAULT, IS_NULLABLE FROM information_schema.columns WHERE TABLE_NAME = 'auth';")

        found = cursor.fetchall()

        if len(found) != 3:
            pass
        elif found[0][0] != 'id' or found[0][1] != 'bigint' or found[0][2] != None or found[0][3] != 'YES':
            pass
        elif found[1][0] != 'try' or found[1][1] != 'int' or found[1][2] != '0' or found[1][3] != 'NO':
            pass
        elif found[2][0] != 'pass' or found[2][1] != 'tinyint(1)' or found[2][2] != '0' or found[2][3] != 'NO':
            pass
        else:
            print('DB Connected')
            return

        print('DB validation failed.')
        print('We will drop the table and re-create it.')
        print('All data will be lost.')

        if input('Continue? (y/n): ') != 'y':
            print('Abort.')
            exit(1)

        cursor.execute("DROP TABLE auth;")
        db.close()
        connect_db()


async def initialize():
    global log

    await bot.wait_until_ready()

    log = logger(LOG_CHANNEL_ID)

    connect_db()

    auth_channel = bot.get_channel(AUTH_CHANNEL_ID)
    await set_channel_perm(auth_channel)

    view = Login()

    await auth_channel.purge(limit=1000)
    await auth_channel.send("대회 사이트 계정으로 로그인 해주세요.", view=view)


@bot.event
async def on_ready():
    await initialize()
    print("Bot is ready.")


@bot.event
async def on_member_join(member: nextcord.Member):
    await member.add_roles(bot.get_guild(SERVER_ID).get_role(AUTH_ROLE_ID))


@bot.event
async def on_error(event, *args, **kwargs):
    await log.error(event, args, kwargs)

bot.run(getenv('BOT_TOKEN'))
