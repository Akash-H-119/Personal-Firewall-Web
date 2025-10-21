from tkinter import ttk, Frame, Label
from .styles import CARD_BG, CARD_FG, FONT_LARGE, FONT_MEDIUM

def create_card(parent, title, value):
    card = Frame(parent, bg=CARD_BG, padx=10, pady=10)
    Label(card, text=title, bg=CARD_BG, fg=CARD_FG, font=FONT_MEDIUM).pack()
    val_label = Label(card, text=value, bg=CARD_BG, fg=CARD_FG, font=FONT_LARGE)
    val_label.pack()
    return card, val_label
