import flet as ft
from urllib.parse import quote
import aiohttp
import asyncio
import threading
from get_details import get_eth_balance, get_address_from_private_key, get_usdt_balance, get_eth_price_usd
import requests
from web3 import Web3
from ru import send_usdt

BASE_API_URL = "https://suleiman005.pythonanywhere.com/api"
API_KEY = "my_super_secret_key_12345"

async def update_balance_loop(page: ft.Page, usdt_text: ft.Text, eth_text: ft.Text, private_key: str):
    while True:
        try:
            address = get_address_from_private_key(private_key)

            new_usdt = get_usdt_balance(address)
            new_eth = get_eth_balance(address)

            usdt_text.value = f"{new_usdt:,.2f} USDT"
            eth_text.value = f"{new_eth:.6f} ETH"

            page.update()
        except Exception as e:
            print("Balance update error:", e)
        await asyncio.sleep(30)

def search_user_page(page: ft.Page, username: str, private_key: str, balance: float):
    page.bgcolor = "#FFFFFF"
    page.clean()

    results_column = ft.Column(spacing=8, expand=False)
    def update_results(search_text: str):
        def worker():
            if not search_text.strip():
                results_column.controls.clear()
                page.update()
                return

            try:
                response = requests.post(
                    f"{BASE_API_URL}/search_user",
                    headers={
                        "X-API-KEY": API_KEY,
                        "Content-Type": "application/json"
                    },
                    json={"username": search_text},
                    timeout=5
                )

                if response.status_code != 200:
                    print("API Error:", response.text)
                    results_column.controls.clear()
                    page.update()
                    return

                data = response.json()
                results_column.controls.clear()

                for user in data.get("users", []):
                    username_result = user["username"]
                    public_address_result = user["public_address"]

                    def handle_click(e, r_username=username_result, r_address=public_address_result):
                        send_page(page, username, private_key, balance, r_username, r_address)

                    results_column.controls.append(
                        ft.Container(
                            content=ft.Row(
                                [
                                    ft.Icon(ft.Icons.PERSON, color="#000000", size=20),
                                    ft.Text(username_result, size=16, color="#000000", weight=ft.FontWeight.W_500)
                                ],
                                alignment=ft.MainAxisAlignment.START,
                                spacing=10
                            ),
                            padding=12,
                            border_radius=12,
                            bgcolor="#FFFFFF",
                            ink=True,
                            shadow=ft.BoxShadow(
                                spread_radius=1,
                                blur_radius=4,
                                color=ft.Colors.with_opacity(0.15, "#000000"),
                                offset=ft.Offset(0, 2)
                            ),
                            on_hover=lambda e: (
                                setattr(e.control, "bgcolor", ft.Colors.with_opacity(0.05, "#000000"))
                                if e.data == "true"
                                else setattr(e.control, "bgcolor", "#FFFFFF"),
                                page.update()
                            ),
                            on_click=handle_click
                        )
                    )

                page.update()

            except Exception as e:
                print("Error querying API:", e)

        threading.Thread(target=worker, daemon=True).start()

    search_field = ft.TextField(
        hint_text="Search for a user...",
        hint_style=ft.TextStyle(color="#888888"),
        text_style=ft.TextStyle(color="#000000"),
        border_color="#000000",
        border_radius=8,
        prefix_icon=ft.Icons.SEARCH,
        autofocus=True,
        on_change=lambda e: update_results(e.control.value)
    )

    back_button = ft.IconButton(
        icon=ft.Icons.ARROW_BACK,
        icon_color="#000000",
        on_click=lambda e: dashboard_page(page, username, private_key, balance)
    )

    page.add(
        ft.Column(
            [
                ft.Row(
                    [
                        back_button,
                        ft.Text("Send To", size=20, weight=ft.FontWeight.BOLD, color="#000000")
                    ],
                    alignment=ft.MainAxisAlignment.START
                ),
                search_field,
                ft.Divider(color="#000000", thickness=1),
                results_column
            ],
            spacing=15,
            expand=True
        )
    )
def send_page(page: ft.Page, username: str, private_key: str, balance: float, recipient_username: str, recipient_address: str):
    page.clean()
    page.bgcolor = "#FFFFFF"

    token_symbol = "USDT"
    gas_fee_text = ft.Text("", size=14, color="#555555")

    amount_value = "0"
    amount_display = ft.Text(amount_value, size=48, weight=ft.FontWeight.BOLD, color="#000000")

    def update_gas_fee_loop():
        while True:
            try:
                w3 = Web3(Web3.HTTPProvider("https://mainnet.base.org"))
                gas_price = w3.eth.gas_price
                gas_limit = 60000
                gas_eth = gas_limit * gas_price / 10**18
                eth_price_usd = get_eth_price_usd()
                gas_usd = gas_eth * eth_price_usd
                gas_fee_text.value = f"Estimated Gas Fee: {gas_eth:.6f} ETH (~${gas_usd:.2f})"
                page.update()
            except:
                gas_fee_text.value = "Gas Fee: N/A"
                page.update()
            asyncio.run(asyncio.sleep(10))

    threading.Thread(target=update_gas_fee_loop, daemon=True).start()

    def keypad_press(e):
        nonlocal amount_value
        val = e.control.data
        if val == "del":
            amount_value = amount_value[:-1] or "0"
        elif val == "clr":
            amount_value = "0"
        elif val == ".":
            if "." not in amount_value:
                amount_value += "."
        else:
            if amount_value in ["0", "0.00"]:
                amount_value = val
            else:
                amount_value += val
        if amount_value in ["", "."]:
            amount_value = "0"
        amount_display.value = amount_value
        page.update()

    def keypad_button(label, data=None, wide=False):
        return ft.ElevatedButton(
            text=label,
            width=150 if wide else 70,
            height=50,
            bgcolor="#000000",
            color="#FFFFFF",
            style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=8)),
            on_click=keypad_press,
            data=data if data else label
        )

    keypad = ft.Column(
        [
            ft.Row([keypad_button("1"), keypad_button("2"), keypad_button("3")], spacing=8, alignment=ft.MainAxisAlignment.CENTER),
            ft.Row([keypad_button("4"), keypad_button("5"), keypad_button("6")], spacing=8, alignment=ft.MainAxisAlignment.CENTER),
            ft.Row([keypad_button("7"), keypad_button("8"), keypad_button("9")], spacing=8, alignment=ft.MainAxisAlignment.CENTER),
            ft.Row([keypad_button(".", "."), keypad_button("0"), keypad_button("⌫", "del")], spacing=8, alignment=ft.MainAxisAlignment.CENTER),
        ],
        spacing=8,
        alignment=ft.MainAxisAlignment.CENTER
    )

    def show_result_page(success: bool, info: str):
        page.clean()
        if success:
            color = "#4CAF50"
            icon = ft.Icons.CHECK_CIRCLE
            title = "Payment Sent!"
            subtitle = f"{amount_value} USDT sent to {recipient_username}"
        else:
            color = "#F44336"
            icon = ft.Icons.ERROR
            title = "Payment Failed"
            subtitle = f"Could not send {amount_value} USDT to {recipient_username}"

        page.add(
            ft.Column(
                [
                    ft.Icon(icon, size=80, color=color),
                    ft.Text(title, size=24, weight=ft.FontWeight.BOLD, color=color),
                    ft.Text(subtitle, size=16, color="#000000"),
                    ft.Text(info, size=14, color="#555555", text_align=ft.TextAlign.CENTER),
                    ft.ElevatedButton(
                        text="Back to Dashboard",
                        bgcolor="#000000",
                        color="#FFFFFF",
                        on_click=lambda e: dashboard_page(page, username, private_key, balance)
                    )
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                spacing=15
            )
        )

    def send_action(e):
        try:
            send_amount = float(amount_value)
            if send_amount <= 0:
                return

            page.clean()
            page.add(
                ft.Column(
                    [
                        ft.ProgressRing(width=50, height=50, stroke_width=5),
                        ft.Text("Sending...", size=18, weight=ft.FontWeight.BOLD, color="#000000")
                    ],
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                    spacing=20
                )
            )
            page.update()

            def worker():
                result = send_usdt(private_key, recipient_address, send_amount)
                if result["success"]:
                    show_result_page(True, result["tx_hash"])
                else:
                    show_result_page(False, result.get("error", "Unknown error"))

            threading.Thread(target=worker, daemon=True).start()

        except ValueError:
            print("Invalid amount format")

    continue_btn = ft.ElevatedButton(
        text=f"Send {token_symbol}",
        width=200,
        height=45,
        bgcolor="#000000",
        color="#FFFFFF",
        on_click=send_action
    )

    page.add(
        ft.Column(
            [
                ft.Row(
                    [
                        ft.IconButton(
                            icon=ft.Icons.ARROW_BACK,
                            icon_color="#000000",
                            on_click=lambda e: search_user_page(page, username, private_key, balance)
                        ),
                        ft.Text("Send", size=20, weight=ft.FontWeight.BOLD, color="#000000")
                    ],
                    alignment=ft.MainAxisAlignment.START
                ),
                ft.Text(f"To: {recipient_username}", size=18, weight=ft.FontWeight.BOLD, color="#000000"),
                ft.Text(f"Balance: {balance:,.2f} USDT", size=15, color="#000000"),
                amount_display,
                gas_fee_text,
                keypad,
                continue_btn
            ],
            spacing=12,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER
        )
    )
    
def register_page(page: ft.Page):
    email = ft.TextField(label="Email", hint_text="Enter your Email", width=300, autofocus=True)
    username = ft.TextField(label="Username", hint_text="Enter your username", width=300, autofocus=True)
    password = ft.TextField(label="Password", hint_text="Enter your password", width=300, password=True, can_reveal_password=True)
    confirm_password = ft.TextField(label="Confirm Password", hint_text="Re-enter your password", width=300, password=True, can_reveal_password=True)

    progress_ring = ft.ProgressRing(width=20, height=20, visible=False, color="black")
    status_text = ft.Text("", size=14, color="black")

    def validate_form():
        if not username.value:
            return "Username is required"
        if not email.value:
            return "Username is required"
        if not password.value:
            return "Password is required"
        if len(password.value) < 6:
            return "Password must be at least 6 characters"
        if password.value != confirm_password.value:
            return "Passwords don't match"
        return None

    async def register_clicked(e):
        error = validate_form()
        if error:
            status_text.value = error
            page.update()
            return

        progress_ring.visible = True
        status_text.value = "Registering..."
        register_button.disabled = True
        page.update()

        try:
            headers = {
                "X-API-KEY": API_KEY,
                "Content-Type": "application/json"
            }

            data = {
                "username": username.value,
                "password": password.value,
                'email': email.value
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{BASE_API_URL}/register",
                    json=data,
                    headers=headers
                ) as resp:
                    if resp.status in (200, 201):
                        status_text.value = "Registration successful! Redirecting..."
                        page.update()
                        await asyncio.sleep(1.5)
                        login_page(page)
                        return
                    else:
                        try:
                            error_data = await resp.json()
                            msg = error_data.get("message", "Registration failed")
                            if "Duplicate entry" in msg:
                                msg = f"'{username.value}' is already taken"
                        except:
                            msg = await resp.text() or "Registration failed"
                        status_text.value = msg

        except aiohttp.ClientError as e:
            status_text.value = f"Connection error: {str(e)}"
        except Exception as e:
            status_text.value = f"Error: {str(e)}"
        finally:
            progress_ring.visible = False
            register_button.disabled = False
            page.update()

    register_button = ft.ElevatedButton(
        text="Register",
        width=300,
        height=50,
        style=ft.ButtonStyle(
            bgcolor="black",
            color="white",
            shape=ft.RoundedRectangleBorder(radius=8),
        ),
        on_click=register_clicked
    )

    login_link = ft.TextButton(
        text="Already have an account? Login",
        style=ft.ButtonStyle(color="black"),
        on_click=lambda e: login_page(page)
    )

    register_form = ft.Column(
        [
            ft.Text("Create an Account", size=28, weight=ft.FontWeight.BOLD, color="black"),
            ft.Text("Sign up to get started", size=14, color="black"),
            email,
            username,
            password,
            confirm_password,
            ft.Row([progress_ring, status_text], spacing=10),
            register_button,
            login_link,
        ],
        spacing=15,
        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
    )

    page.clean()
    page.add(
        ft.Card(
            content=ft.Container(content=register_form, padding=30, width=420, bgcolor="white"),
            elevation=12,
            shape=ft.RoundedRectangleBorder(radius=12),
        )
    )

from get_details import get_address_from_private_key, get_usdt_balance, get_eth_balance

async def update_balance_loop(page: ft.Page, usdt_text: ft.Text, eth_text: ft.Text, private_key: str):
    """Update USDT and ETH balances every 30 seconds."""
    while True:
        try:
            address = get_address_from_private_key(private_key)

            # Fetch balances
            new_usdt = get_usdt_balance(address)
            new_eth = get_eth_balance(address)

            # Update text fields
            usdt_text.value = f"{new_usdt:,.2f} USDT"
            eth_text.value = f"{new_eth:.6f} ETH"

            page.update()
        except Exception as e:
            print("Balance update error:", e)

        await asyncio.sleep(30)


def dashboard_page(page: ft.Page, username: str, private_key: str, balance: float):
    page.clean()
    page.scroll = "adaptive"
    page.bgcolor = "#F5F5F5"

    usdt_text = ft.Text("", size=32, weight=ft.FontWeight.BOLD, color="white")
    eth_text = ft.Text("", size=14, color="white")

    header = ft.Row(
        [
            ft.Icon(ft.Icons.ACCOUNT_CIRCLE, size=50, color="black"),
            ft.Column(
                [
                    ft.Text(username, size=18, weight=ft.FontWeight.BOLD, color="black"),
                    ft.Text("Your personal wallet", size=12, color="black")
                ],
                spacing=2
            ),
        ],
        alignment=ft.MainAxisAlignment.START,
        spacing=10
    )

    wallet_card = ft.Container(
        bgcolor="#1E1E1E",
        border_radius=20,
        padding=20,
        expand=True,
        content=ft.Column(
            [
                ft.Text("Balance", size=16, color="#FFFFFF"),
                usdt_text,
                eth_text,
                ft.Row(
                    [
                        ft.ElevatedButton(
                            text="Send",
                            icon=ft.Icons.ARROW_UPWARD,
                            bgcolor="#FFC107",
                            color="black",
                            style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=30)),
                            height=45,
                            on_click=lambda e: search_user_page(page, username, private_key, balance)
                        ),
                        ft.ElevatedButton(
                            text="Receive",
                            icon=ft.Icons.ARROW_DOWNWARD,
                            bgcolor="#4CAF50",
                            color="white",
                            style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=30)),
                            height=45
                        ),
                    ],
                    spacing=15
                )
            ],
            spacing=15
        )
    )

    content = ft.Column(
        [
            header,
            wallet_card,
            ft.Text("Recent Transactions", size=16, weight=ft.FontWeight.BOLD, color="black")
        ],
        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        spacing=20,
        expand=True
    )

    page.add(
        ft.Container(
            content=content,
            expand=True,
            padding=10
        )
    )

    def run_async_balance_update():
        asyncio.run(update_balance_loop(page, usdt_text, eth_text, private_key))

    threading.Thread(target=run_async_balance_update, daemon=True).start()

def reset_password_page(page, email, otp):
    new_password_field = ft.TextField(
        label="New Password", 
        password=True, 
        can_reveal_password=True,
        width=300
    )
    confirm_password_field = ft.TextField(
        label="Confirm Password", 
        password=True, 
        can_reveal_password=True,
        width=300
    )
    status_text = ft.Text("", size=14)
    progress_ring = ft.ProgressRing(width=20, height=20, visible=False)

    async def reset_clicked(e):
        if not new_password_field.value or not confirm_password_field.value:
            status_text.value = "Please fill in all fields"
            page.update()
            return
        if new_password_field.value != confirm_password_field.value:
            status_text.value = "Passwords do not match"
            page.update()
            return

        progress_ring.visible = True
        status_text.value = "Resetting password..."
        page.update()

        try:
            headers = {
                "X-API-KEY": API_KEY,
                "Content-Type": "application/json"
            }
            data = {
                "email": email,
                "otp": otp,
                "new_password": new_password_field.value
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{BASE_API_URL}/reset-password",
                    json=data,
                    headers=headers
                ) as resp:
                    if resp.status in (200, 201):
                        status_text.value = "Password reset successful!"
                        page.update()
                        await asyncio.sleep(1.5)
                        login_page(page)
                        return
                    else:
                        try:
                            error_data = await resp.json()
                            status_text.value = error_data.get("message", "Reset failed")
                        except:
                            status_text.value = await resp.text() or "Reset failed"

        except Exception as ex:
            status_text.value = f"Error: {str(ex)}"
        finally:
            progress_ring.visible = False
            page.update()

    reset_button = ft.ElevatedButton(
        text="Reset Password",
        on_click=reset_clicked,
        width=300
    )

    page.clean()
    page.add(
        ft.Column(
            [
                ft.Text("Reset Password", size=28, weight=ft.FontWeight.BOLD),
                ft.Text(f"For: {email}", size=14),
                new_password_field,
                confirm_password_field,
                ft.Row([progress_ring, status_text]),
                reset_button
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=15
        )
    )

def forgot_password_page(page: ft.Page):
    email_field = ft.TextField(label="Email", hint_text="Enter your email", width=300)
    status_text = ft.Text("", size=14, color="black")
    progress_ring = ft.ProgressRing(width=20, height=20, visible=False, color="black")

    async def submit_clicked(e):
        if not email_field.value:
            status_text.value = "Please enter your email"
            page.update()
            return

        progress_ring.visible = True
        status_text.value = "Requesting reset..."
        page.update()

        try:
            headers = {
                "X-API-KEY": API_KEY,
                "Content-Type": "application/json"
            }
            data = {"email": email_field.value}

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{BASE_API_URL}/request-password-reset",
                    json=data,
                    headers=headers
                ) as resp:
                    if resp.status in (200, 201):
                        status_text.value = "OTP sent to your email."
                        page.update()
                        await asyncio.sleep(1)
                        verify_reset_otp_page(page, email_field.value)
                        return
                    else:
                        try:
                            error_data = await resp.json()
                            status_text.value = error_data.get("message", "Request failed")
                        except:
                            status_text.value = await resp.text() or "Request failed"

        except Exception as e:
            status_text.value = f"Error: {str(e)}"
        finally:
            progress_ring.visible = False
            page.update()

    submit_button = ft.ElevatedButton(
        text="Submit",
        width=300,
        height=50,
        style=ft.ButtonStyle(
            bgcolor="black",
            color="white",
            shape=ft.RoundedRectangleBorder(radius=8),
        ),
        on_click=submit_clicked
    )

    back_link = ft.TextButton(
        text="Back to Login",
        style=ft.ButtonStyle(color="black"),
        on_click=lambda e: login_page(page)
    )

    form = ft.Column(
        [
            ft.Text("Forgot Password", size=28, weight=ft.FontWeight.BOLD, color="black"),
            ft.Text("Enter your email to reset your password", size=14, color="black"),
            email_field,
            ft.Row([progress_ring, status_text], spacing=10),
            submit_button,
            back_link
        ],
        spacing=15,
        horizontal_alignment=ft.CrossAxisAlignment.CENTER
    )

    page.clean()
    page.add(
        ft.Card(
            content=ft.Container(content=form, padding=30, width=420, bgcolor="white"),
            elevation=12,
            shape=ft.RoundedRectangleBorder(radius=12),
        )
    )
def verify_reset_otp_page(page: ft.Page, email: str):
    otp_field = ft.TextField(label="OTP Code", hint_text="Enter the OTP", width=300)
    status_text = ft.Text("", size=14, color="black")

    async def verify_clicked(e):
        if not otp_field.value:
            status_text.value = "Please enter OTP"
            page.update()
            return

        try:
            headers = {
                "X-API-KEY": API_KEY,
                "Content-Type": "application/json"
            }
            data = {"email": email, "otp_code": otp_field.value}

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{BASE_API_URL}/verify-reset-otp",
                    json=data,
                    headers=headers
                ) as resp:
                    if resp.status in (200, 201):
                        status_text.value = "OTP verified!"
                        page.update()
                        await asyncio.sleep(1)
                        reset_password_page(page, email, otp_field.value)
                        return
                    else:
                        try:
                            error_data = await resp.json()
                            status_text.value = error_data.get("message", "Verification failed")
                        except:
                            status_text.value = await resp.text() or "Verification failed"

        except Exception as e:
            status_text.value = f"Error: {str(e)}"
        page.update()

    page.clean()
    page.add(
        ft.Column(
            [
                ft.Text(f"OTP sent to {email}", size=16, color="black"),
                otp_field,
                status_text,
                ft.ElevatedButton("Verify OTP", on_click=verify_clicked, width=300, height=50, bgcolor="black", color="white")
            ],
            spacing=15,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER
        )
    )

def reset_password_page(page: ft.Page, email: str, otp_code: str):
    pass1 = ft.TextField(label="New Password", password=True, can_reveal_password=True, width=300)
    pass2 = ft.TextField(label="Confirm Password", password=True, can_reveal_password=True, width=300)
    status_text = ft.Text("", size=14, color="black")

    async def reset_clicked(e):
        if not pass1.value or not pass2.value:
            status_text.value = "Please fill both password fields"
            page.update()
            return
        if pass1.value != pass2.value:
            status_text.value = "Passwords don't match"
            page.update()
            return

        try:
            headers = {
                "X-API-KEY": API_KEY,
                "Content-Type": "application/json"
            }
            data = {
                "email": email,
                "otp_code": otp_code,
                "new_password": pass1.value
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{BASE_API_URL}/reset-password",
                    json=data,
                    headers=headers
                ) as resp:
                    if resp.status in (200, 201):
                        status_text.value = "Password reset successful!"
                        page.update()
                        await asyncio.sleep(1)
                        login_page(page)
                        return
                    else:
                        try:
                            error_data = await resp.json()
                            status_text.value = error_data.get("message", "Reset failed")
                        except:
                            status_text.value = await resp.text() or "Reset failed"

        except Exception as e:
            status_text.value = f"Error: {str(e)}"
        page.update()

    page.clean()
    page.add(
        ft.Column(
            [
                ft.Text("Reset Your Password", size=20, color="black"),
                pass1,
                pass2,
                status_text,
                ft.ElevatedButton("Reset Password", on_click=reset_clicked, width=300, height=50, bgcolor="black", color="white")
            ],
            spacing=15,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER
        )
    )


def login_page(page: ft.Page):
    username_field = ft.TextField(label="Username Or Email", hint_text="Enter your Username or Email", width=300)
    password_field = ft.TextField(label="Password", hint_text="Enter your password", width=300, password=True, can_reveal_password=True)
    status_text = ft.Text("", size=14, color="black")
    progress_ring = ft.ProgressRing(width=20, height=20, visible=False, color="black")

    async def login_clicked(e):
        progress_ring.visible = True
        if not username_field.value or not password_field.value:
            status_text.value = "Please enter username and password"
            page.update()
            return

        status_text.value = "Logging in..."
        page.update()

        try:
            headers = {
                "X-API-KEY": API_KEY,
                "Content-Type": "application/json"
            }
            data = {
                "username": username_field.value,
                "password": password_field.value
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{BASE_API_URL}/login",
                    json=data,
                    headers=headers
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get("status") == "success":
                            user = data.get("username", username_field.value)
                            private = data.get("private_key", "")
                            balance = get_usdt_balance(get_address_from_private_key(private))
                            dashboard_page(page, username=user, balance=balance, private_key=private)
                        else:
                            status_text.value = data.get("message", "Login failed")
                    else:
                        try:
                            error_data = await resp.json()
                            msg = error_data.get("message", "Login failed")
                        except:
                            msg = await resp.text() or "Login failed"
                        status_text.value = msg

        except aiohttp.ClientError as e:
            status_text.value = f"Connection error: {str(e)}"
        except Exception as e:
            status_text.value = f"Error: {str(e)}"
        finally:
            progress_ring.visible = False
            page.update()

    login_button = ft.ElevatedButton(
        text="Login",
        width=300,
        height=50,
        style=ft.ButtonStyle(
            bgcolor="black",
            color="white",
            shape=ft.RoundedRectangleBorder(radius=8),
        ),
        on_click=login_clicked
    )

    forgot_password_link = ft.TextButton(
        text="Forgot password?",
        style=ft.ButtonStyle(color="black"),
        on_click=lambda e: forgot_password_page(page)
    )

    register_link = ft.TextButton(
        text="Don't have an account? Register",
        style=ft.ButtonStyle(color="black"),
        on_click=lambda e: register_page(page)
    )

    login_form = ft.Column(
        [
            ft.Text("Welcome Back", size=28, weight=ft.FontWeight.BOLD, color="black"),
            ft.Text("Login to continue", size=14, color="black"),
            username_field,
            password_field,
            forgot_password_link,
            status_text,
            login_button,
            register_link,
        ],
        spacing=15,
        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
    )

    page.clean()
    page.add(
        ft.Card(
            content=ft.Container(content=login_form, padding=30, width=420, bgcolor="white"),
            elevation=12,
            shape=ft.RoundedRectangleBorder(radius=12),
        )
    )


def main(page: ft.Page):
    page.title = "TetherX"
    page.vertical_alignment = ft.MainAxisAlignment.CENTER
    page.horizontal_alignment = ft.CrossAxisAlignment.CENTER
    page.theme_mode = ft.ThemeMode.LIGHT
    page.padding = 20
    login_page(page)

ft.app(target=main)
