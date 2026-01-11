import sys
from PySide6 import QtWidgets

# Ensure src root is on sys.path when running directly
import os
SRC_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if SRC_ROOT not in sys.path:
    sys.path.append(SRC_ROOT)

from ui.main_window import MainWindow


def main():
    app = QtWidgets.QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
