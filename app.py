import nextcord
from nextcord.ext import commands

from passlib.hash import bcrypt_sha256
import MySQLdb

SERVER_ID = 881780702004252692
AUTH_CHANNEL_ID = 1071731879415394305
AUTH_ROLE_ID = 1071725158320054302

# TODO : 인증 로그 구현
#      : 입력 시도 제한
#      : env 생성


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
        cursor = db.cursor()
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


async def initialize():
    await bot.wait_until_ready()

    auth_channel = bot.get_channel(AUTH_CHANNEL_ID)
    await set_channel_perm(auth_channel)

    view = Login()

    await auth_channel.purge(limit=1000)
    await auth_channel.send("대회 사이트 계정으로 로그인 해주세요.", view=view)


@bot.event
async def on_ready():
    print("Bot is ready.")
    await initialize()


@bot.event
async def on_member_join(member: nextcord.Member):
    await member.add_roles(bot.get_guild(SERVER_ID).get_role(AUTH_ROLE_ID))

if __name__ == "__main__":
    db = MySQLdb.connect(
        host='localhost', port=3306, user='root', passwd='cksdls123', db='ctfd')

    print('DB Connected')

bot.run("MTA3MTY5MjUyODU2MDExOTgzOA.GcGGFf.dnz8zwdo1O0wNP4ST2Jy9xGiHY6ICgWx0_Rt2E")
