"""Графический клиент банковской системы с AES-GCM-защитой (ЛР3)."""

from __future__ import annotations

import socket
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import scrolledtext, ttk

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from client.client import BankingClient
from config import get_settings
from crypto.errors import CryptoError
from logging_setup import setup_logging
from protocol.messages import MessageType, Request, Response


class BankingClientUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Банковская система — BSP v1.0 / AES-256-GCM")
        self.root.geometry("780x700")
        self.root.configure(bg="#f0f0f0")

        self.settings = get_settings()
        self.client: BankingClient | None = None
        self.connected = False

        self.create_widgets()
        self.configure_tags()

    # ── Интерфейс ────────────────────────────────────────────────────────

    def create_widgets(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background="#f0f0f0")
        style.configure("TLabelframe", background="#f0f0f0")
        style.configure("TLabelframe.Label", font=("Segoe UI", 10, "bold"))
        style.configure("TButton", font=("Segoe UI", 9))
        style.configure("TLabel", background="#f0f0f0", font=("Segoe UI", 9))

        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)

        # ── Подключение ──
        conn_frame = ttk.LabelFrame(
            main_frame, text="Подключение", padding="10"
        )
        conn_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)
        conn_frame.columnconfigure(1, weight=1)

        ttk.Label(conn_frame, text="Хост:").grid(
            row=0, column=0, sticky=tk.W, padx=5
        )
        self.host_entry = ttk.Entry(conn_frame)
        self.host_entry.insert(0, self.settings.host)
        self.host_entry.grid(
            row=0, column=1, sticky=(tk.W, tk.E), padx=5
        )

        ttk.Label(conn_frame, text="Порт:").grid(
            row=0, column=2, sticky=tk.W, padx=5
        )
        self.port_entry = ttk.Entry(conn_frame, width=8)
        self.port_entry.insert(0, str(self.settings.port))
        self.port_entry.grid(row=0, column=3, sticky=tk.W, padx=5)

        self.connect_btn = ttk.Button(
            conn_frame,
            text="Подключиться",
            command=self.toggle_connection,
        )
        self.connect_btn.grid(row=0, column=4, padx=5)

        self.crypto_label = ttk.Label(
            conn_frame,
            text="Криптография: AES-256-GCM (ключ не отображается)",
            foreground="#555555",
        )
        self.crypto_label.grid(
            row=1, column=0, columnspan=5, sticky=tk.W, padx=5, pady=(6, 0)
        )

        # ── Получение баланса ──
        acc_frame = ttk.LabelFrame(
            main_frame, text="Получение баланса", padding="10"
        )
        acc_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
        acc_frame.columnconfigure(1, weight=1)

        ttk.Label(acc_frame, text="Номер счёта:").grid(
            row=0, column=0, sticky=tk.W, padx=5
        )
        self.acc_id_entry = ttk.Entry(acc_frame)
        self.acc_id_entry.insert(0, "ACC-1001")
        self.acc_id_entry.grid(
            row=0, column=1, sticky=(tk.W, tk.E), padx=5
        )

        self.get_balance_btn = ttk.Button(
            acc_frame,
            text="Получить баланс",
            command=self.get_balance,
            state=tk.DISABLED,
        )
        self.get_balance_btn.grid(row=0, column=2, padx=5)

        # ── Перевод средств ──
        trans_frame = ttk.LabelFrame(
            main_frame, text="Перевод средств", padding="10"
        )
        trans_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=5)
        trans_frame.columnconfigure(1, weight=1)

        ttk.Label(trans_frame, text="От:").grid(
            row=0, column=0, sticky=tk.W, padx=5, pady=2
        )
        self.from_acc_entry = ttk.Entry(trans_frame)
        self.from_acc_entry.insert(0, "ACC-1001")
        self.from_acc_entry.grid(
            row=0, column=1, sticky=(tk.W, tk.E), padx=5, pady=2
        )

        ttk.Label(trans_frame, text="Кому:").grid(
            row=1, column=0, sticky=tk.W, padx=5, pady=2
        )
        self.to_acc_entry = ttk.Entry(trans_frame)
        self.to_acc_entry.insert(0, "ACC-1002")
        self.to_acc_entry.grid(
            row=1, column=1, sticky=(tk.W, tk.E), padx=5, pady=2
        )

        ttk.Label(trans_frame, text="Сумма:").grid(
            row=2, column=0, sticky=tk.W, padx=5, pady=2
        )
        self.amount_entry = ttk.Entry(trans_frame)
        self.amount_entry.insert(0, "100.0")
        self.amount_entry.grid(
            row=2, column=1, sticky=(tk.W, tk.E), padx=5, pady=2
        )

        self.transfer_btn = ttk.Button(
            trans_frame,
            text="Перевести",
            command=self.transfer,
            state=tk.DISABLED,
        )
        self.transfer_btn.grid(row=3, column=1, pady=5)

        # ── Лог ──
        log_frame = ttk.LabelFrame(
            main_frame, text="Результаты", padding="10"
        )
        log_frame.grid(
            row=3, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5
        )
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(3, weight=1)

        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            height=22,
            width=92,
            font=("Consolas", 10),
            bg="#1e1e1e",
            fg="#d4d4d4",
            insertbackground="white",
        )
        self.log_text.grid(
            row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S)
        )

        clear_btn = ttk.Button(
            log_frame, text="Очистить лог", command=self.clear_log
        )
        clear_btn.grid(row=1, column=0, pady=(5, 0))

    def configure_tags(self) -> None:
        self.log_text.tag_configure(
            "header", foreground="#569cd6", font=("Consolas", 10, "bold")
        )
        self.log_text.tag_configure("success", foreground="#4ec9b0")
        self.log_text.tag_configure("error", foreground="#f48771")
        self.log_text.tag_configure("info", foreground="#dcdcaa")
        self.log_text.tag_configure("label", foreground="#9cdcfe")
        self.log_text.tag_configure("value", foreground="#ce9178")
        self.log_text.tag_configure("separator", foreground="#555555")
        self.log_text.tag_configure("system", foreground="#c586c0")
        self.log_text.tag_configure("crypto", foreground="#b5cea8")

    def log(self, text: str, tag: str | None = None) -> None:
        if tag:
            self.log_text.insert(tk.END, text + "\n", tag)
        else:
            self.log_text.insert(tk.END, text + "\n")
        self.log_text.see(tk.END)

    def clear_log(self) -> None:
        self.log_text.delete("1.0", tk.END)

    # ── Соединение ───────────────────────────────────────────────────────

    def toggle_connection(self) -> None:
        if not self.connected:
            self.connect()
        else:
            self.disconnect()

    def connect(self) -> None:
        host = self.host_entry.get().strip()
        try:
            port = int(self.port_entry.get().strip())
        except ValueError:
            self.log("Неверный формат порта", "error")
            return

        try:
            client = BankingClient(self.settings)
            client.connect(host, port)

            self.client = client
            self.connected = True
            self.connect_btn.config(text="Отключиться")
            self.get_balance_btn.config(state=tk.NORMAL)
            self.transfer_btn.config(state=tk.NORMAL)

            info = client.crypto.describe()
            self.crypto_label.config(
                text=(
                    f"Криптография: {info['algorithm']} · "
                    f"key_id={info['key_id']} · "
                    f"fingerprint={info['key_fingerprint']}"
                )
            )
            self.log(f"● Подключено к {host}:{port}", "success")
            self.log(
                f"● Канал защищён: {info['algorithm']}, "
                f"key_id={info['key_id']}",
                "crypto",
            )

            self.send_request_async(
                Request(type=MessageType.HELLO), "HELLO"
            )
        except CryptoError as exc:
            self.log(f"✖ Ошибка криптоконфигурации: {exc}", "error")
        except Exception as exc:  # noqa: BLE001
            self.log(f"✖ Ошибка подключения: {exc}", "error")

    def disconnect(self) -> None:
        if self.client is not None:
            self.client.close()
            self.client = None
        self.connected = False

        self.connect_btn.config(text="Подключиться")
        self.get_balance_btn.config(state=tk.DISABLED)
        self.transfer_btn.config(state=tk.DISABLED)
        self.crypto_label.config(
            text="Криптография: AES-256-GCM (ключ не отображается)"
        )
        self.log("● Отключено от сервера", "system")

    # ── Асинхронные запросы ──────────────────────────────────────────────

    def send_request_async(self, request: Request, operation_name: str) -> None:
        client = self.client
        if client is None:
            self.log("Не подключено к серверу", "error")
            return

        def task() -> None:
            try:
                response = client.request(request)
                meta = {
                    "request_nonce": client.last_request_envelope.nonce
                    if client.last_request_envelope
                    else b"",
                    "response_nonce": client.last_response_envelope.nonce
                    if client.last_response_envelope
                    else b"",
                    "key_id": client.last_response_envelope.key_id
                    if client.last_response_envelope
                    else "-",
                    "ciphertext_bytes": len(
                        client.last_response_envelope.ciphertext
                    )
                    if client.last_response_envelope
                    else 0,
                }
                self.root.after(
                    0,
                    lambda: self.display_response(
                        operation_name, response, meta
                    ),
                )
            except socket.timeout:
                self.root.after(
                    0,
                    lambda: self.log(
                        f"[{operation_name}] ✖ Тайм-аут ожидания ответа",
                        "error",
                    ),
                )
            except CryptoError as exc:
                self.root.after(
                    0,
                    lambda: self.log(
                        f"[{operation_name}] ✖ Ошибка аутентификации: {exc}",
                        "error",
                    ),
                )
            except Exception as exc:  # noqa: BLE001
                self.root.after(
                    0,
                    lambda: self.log(
                        f"[{operation_name}] ✖ Ошибка: {exc}", "error"
                    ),
                )

        threading.Thread(target=task, daemon=True).start()

    def display_response(
        self,
        operation_name: str,
        response: Response,
        meta: dict,
    ) -> None:
        if not isinstance(response, Response):
            self.log(
                f"[{operation_name}] ✖ Некорректный ответ сервера", "error"
            )
            return

        status_tag = "success" if response.is_success else "error"
        status_icon = "✔" if response.is_success else "✖"

        self.log("─" * 62, "separator")
        self.log(f"[{operation_name}]", "header")
        self.log(f"  request_id : {response.request_id}", "info")
        self.log(
            f"  status     : {status_icon} {response.status}", status_tag
        )

        if response.payload is not None:
            self.log("  payload:", "label")
            for key, value in response.payload.items():
                self.log(f"    • {key:<15}: {value}", "value")

        if response.error is not None:
            self.log("  error:", "label")
            self.log(f"    • code    : {response.error.code}", "error")
            self.log(
                f"    • message : {response.error.message}", "error"
            )

        self.log("  защита канала:", "label")
        self.log(
            f"    • algorithm : AES-256-GCM\n"
            f"    • key_id    : {meta.get('key_id', '-')}\n"
            f"    • req nonce : {meta.get('request_nonce', b'').hex()}\n"
            f"    • resp nonce: {meta.get('response_nonce', b'').hex()}\n"
            f"    • ciphertext: {meta.get('ciphertext_bytes', 0)} байт",
            "crypto",
        )

        self.log("─" * 62, "separator")
        self.log("")

    # ── Действия пользователя ────────────────────────────────────────────

    def get_balance(self) -> None:
        if not self.connected or self.client is None:
            self.log("Не подключено к серверу", "error")
            return

        account_id = self.acc_id_entry.get().strip()
        if not account_id:
            self.log("Введите номер счёта", "error")
            return

        request = Request(
            type=MessageType.ACCOUNT_GET,
            payload={"account_id": account_id},
        )
        self.send_request_async(request, "ACCOUNT_GET")

    def transfer(self) -> None:
        if not self.connected or self.client is None:
            self.log("Не подключено к серверу", "error")
            return

        from_acc = self.from_acc_entry.get().strip()
        to_acc = self.to_acc_entry.get().strip()
        amount_str = self.amount_entry.get().strip()

        if not from_acc or not to_acc or not amount_str:
            self.log("Заполните все поля", "error")
            return

        try:
            amount = float(amount_str)
        except ValueError:
            self.log("Сумма должна быть числом", "error")
            return

        request = Request(
            type=MessageType.TRANSFER,
            payload={"from": from_acc, "to": to_acc, "amount": amount},
        )
        self.send_request_async(request, "TRANSFER")


def main() -> None:
    setup_logging("client.client_ui", get_settings())
    root = tk.Tk()
    BankingClientUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
