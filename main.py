from kivy.core.window import Window
from gui import Hping3GUIApp
    
def main():
    # Set the window background to a dark theme
    Window.clearcolor = (0.1, 0.1, 0.1, 1)
    Hping3GUIApp().run()

if __name__ == '__main__':
    main()