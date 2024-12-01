import subprocess
import ipaddress
import socket

from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.spinner import Spinner
from kivy.uix.scrollview import ScrollView
from kivy.uix.checkbox import CheckBox
from kivy.uix.gridlayout import GridLayout

class Hping3GUIApp(App):
    def build(self):
        # Main vertical layout
        main_layout = BoxLayout(orientation='vertical', padding=10, spacing=10)
        
        # Target Configuration
        target_layout = GridLayout(cols=2, size_hint_y=None, height=200)
        
        # Target IP/Hostname
        target_layout.add_widget(Label(text='Target:'))
        self.target_input = TextInput(
            multiline=False, 
            hint_text='IP or Hostname',
            size_hint_x=0.8
        )
        target_layout.add_widget(self.target_input)
        
        # Scan Type Selection
        target_layout.add_widget(Label(text='Scan Type:'))
        self.scan_type_spinner = Spinner(
            text='TCP SYN Ping',
            values=(
                'TCP SYN Ping', 
                'UDP Ping', 
                'ICMP Echo Ping', 
                'TCP ACK Ping', 
                'SYN Flood', 
                'UDP Flood'
            ),
            size_hint_x=0.8
        )
        target_layout.add_widget(self.scan_type_spinner)
        
        # Port Configuration
        target_layout.add_widget(Label(text='Port:'))
        self.port_input = TextInput(
            multiline=False, 
            hint_text='Target Port (e.g., 80, 443)',
            size_hint_x=0.8
        )
        target_layout.add_widget(self.port_input)
        
        # Packet Count
        target_layout.add_widget(Label(text='Packet Count:'))
        self.packet_count_input = TextInput(
            multiline=False, 
            hint_text='Number of packets (default: 5)',
            size_hint_x=0.8
        )
        target_layout.add_widget(self.packet_count_input)
        
        # Advanced Options
        advanced_layout = GridLayout(cols=2, size_hint_y=None, height=150)
        
        # Flood Option
        advanced_layout.add_widget(Label(text='Flood Mode:'))
        self.flood_check = CheckBox()
        advanced_layout.add_widget(self.flood_check)
        
        # Random Source IP
        advanced_layout.add_widget(Label(text='Spoof Source IP:'))
        self.spoof_check = CheckBox()
        advanced_layout.add_widget(self.spoof_check)
        
        # Verbosity Level
        advanced_layout.add_widget(Label(text='Verbosity:'))
        self.verbosity_spinner = Spinner(
            text='Normal',
            values=('Quiet', 'Normal', 'Verbose'),
            size_hint_x=0.8
        )
        advanced_layout.add_widget(self.verbosity_spinner)
        
        # Buttons Layout
        buttons_layout = BoxLayout(size_hint_y=None, height=50)
        
        # Scan Button
        scan_button = Button(
            text='Run Hping3 Scan', 
            on_press=self.run_hping3_scan,
            size_hint_x=0.7
        )
        buttons_layout.add_widget(scan_button)
        
        # Clear Output Button
        clear_button = Button(
            text='Clear Output', 
            on_press=self.clear_output,
            size_hint_x=0.3,
            background_color=[0.8, 0.2, 0.2, 1]  # Red-ish color for visibility
        )
        buttons_layout.add_widget(clear_button)
        
        # Results Area
        results_label = Label(text='Scan Results:', size_hint_y=None, height=50)
        scroll_view = ScrollView()
        self.results_text = TextInput(
            readonly=True, 
            multiline=True,
            background_color=[1, 1, 1, 0.1],
            foreground_color=[1, 1, 1, 1]
        )
        scroll_view.add_widget(self.results_text)
        
        # Assemble Main Layout
        main_layout.add_widget(target_layout)
        main_layout.add_widget(advanced_layout)
        main_layout.add_widget(buttons_layout)
        main_layout.add_widget(results_label)
        main_layout.add_widget(scroll_view)
        
        return main_layout
    
    def clear_output(self, instance):
        """
        Clear the results text area
        """
        self.results_text.text = ''
    
    def validate_input(self, target):
        """Validate target input"""
        try:
            # Try to validate as IP
            ipaddress.ip_address(target)
            return True
        except ValueError:
            try:
                # Attempt to resolve hostname
                socket.gethostbyname(target)
                return True
            except:
                return False
    
    def run_hping3_scan(self, instance):
        # Clear previous results
        self.results_text.text = ''
        
        # Validate target
        target = self.target_input.text.strip()
        if not target or not self.validate_input(target):
            self.results_text.text = 'Error: Invalid target IP or hostname'
            return
        
        # Prepare Hping3 command base
        hping_cmd = ['sudo', 'hping3']
        
        # Add scan type specific options
        scan_type = self.scan_type_spinner.text
        port = self.port_input.text.strip()
        
        # Port validation
        try:
            if port:
                port_num = int(port)
                if port_num < 1 or port_num > 65535:
                    raise ValueError("Invalid port number")
            else:
                port_num = 80  # Default to port 80
        except ValueError:
            self.results_text.text = 'Error: Invalid port number'
            return
        
        # Scan type configuration
        if scan_type == 'TCP SYN Ping':
            hping_cmd.extend(['-S', '-p', str(port_num)])
        elif scan_type == 'UDP Ping':
            hping_cmd.extend(['-2', '-p', str(port_num)])
        elif scan_type == 'ICMP Echo Ping':
            hping_cmd.append('-1')
        elif scan_type == 'TCP ACK Ping':
            hping_cmd.extend(['-A', '-p', str(port_num)])
        elif scan_type == 'SYN Flood':
            hping_cmd.extend(['-S', '-p', str(port_num), '--flood'])
        elif scan_type == 'UDP Flood':
            hping_cmd.extend(['-2', '-p', str(port_num), '--flood'])
        
        # Packet count
        packet_count = self.packet_count_input.text.strip()
        try:
            if packet_count:
                count = int(packet_count)
                hping_cmd.extend(['-c', str(count)])
            else:
                hping_cmd.extend(['-c', '5'])  # Default 5 packets
        except ValueError:
            self.results_text.text = 'Error: Invalid packet count'
            return
        
        # Flood mode
        if self.flood_check.active:
            hping_cmd.append('--flood')
        
        # Spoof source IP
        if self.spoof_check.active:
            hping_cmd.append('--rand-source')
        
        # Verbosity
        verbosity = self.verbosity_spinner.text
        if verbosity == 'Quiet':
            hping_cmd.append('-q')
        elif verbosity == 'Verbose':
            hping_cmd.append('-V')
        
        # Add target
        hping_cmd.append(target)
        
        try:
            # Run Hping3 scan
            result = subprocess.run(
                hping_cmd, 
                capture_output=True, 
                text=True, 
                timeout=120  # 2-minute timeout
            )
            
            # Display results
            self.results_text.text = result.stdout or result.stderr
        
        except subprocess.TimeoutExpired:
            self.results_text.text = 'Scan timed out. Target may be unresponsive.'
        except PermissionError:
            self.results_text.text = 'Error: Hping3 requires root/sudo privileges.'
        except FileNotFoundError:
            self.results_text.text = 'Error: Hping3 is not installed. Please install using:\nsudo apt-get install hping3'
        except Exception as e:
            self.results_text.text = f'Error: {str(e)}'