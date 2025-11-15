# After running book_seed_builder.py and generating book_seed.txt
import keybook

with open("book_seed.txt", "rb") as f:
    book_bytes = f.read()  # already normalized & packed

# If you want to use it to create a vault, swap this into your init path
# (e.g., temporarily replace _assemble_book to just return book_bytes),
# or write a tiny init function variant that accepts prebuilt book bytes.
