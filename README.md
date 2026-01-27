<h1 align="center">🌹 PacketBloom</h1>

<p align="center">
A modular packet analysis toolkit built with Python and C++ (libpcap + pybind11).
PacketBloom captures, analyzes, and visualizes network flows with a clean, banner-styled CLI.
</p>

<hr/>

<pre>
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⡞⢀⣾⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⠀⣼⣿⣿⣿⡏⠉⠙⠛⠃⠸⠿⣿⣿⣿⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣤⣤⡄⠸⣿⣿⣦⡈⢻⣿⣿⡇⣾⣿⣿⣷⣶⠀⢸⣿⣿⡆⠀
⠀⠀⠀⠀⠀⠀⠀⠙⠿⣷⠀⣿⣿⣿⣷⣄⠙⣿⣧⣈⣉⣀⣿⣿⠀⢸⣿⣿⡇⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⣿⣿⣿⣧⡈⠻⠿⠿⠛⠛⠛⠃⢸⣿⣿⡇⠀
⠀⠀⠀⠀⠀⠀⠀⢀⣠⣶⣧⡈⠛⠿⣿⣿⣿⣿⣶⣶⣶⣶⣶⣿⣿⣿⠿⠛⠁⠀
⠀⠀⠀⠀⠀⠀⣰⣿⣿⣿⣿⣿⠷⠂⢀⠙⠻⢿⣿⣿⣿⣿⡿⠟⢋⣡⣄⠀⠀⠀
⠀⠀⠀⠀⠀⠈⠉⠉⠉⠉⠉⠀⢰⣾⣿⡀⢰⣤⣈⠙⢋⣡⠀⠘⠻⠿⢿⣷⡀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⡿⠛⠃⠈⠻⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣟⡀⡀⠀⠀⠀⠉⠿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣴⡀⠀⣠⣾⠿⠿⠿⠛⠁⠀⠀⠀⠀⠀⠀⠙⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠸⣿⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠒⠛⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
</pre>

<hr/>

<h2>✨ Features</h2>
<ul>
  <li><b>Live Capture:</b> Capture packets directly from your network interface (default max: 1000).</li>
  <li><b>PCAP Export:</b> Save captured traffic into a <code>.pcap</code> file for Wireshark or other tools.</li>
  <li><b>Flow Analysis:</b> Summarize traffic flows (SRC_IP, DST_IP, protocol, packet count, bytes).</li>
  <li><b>Anomaly Detection:</b> Built-in rules highlight suspicious traffic patterns.</li>
  <li><b>Menu Banner:</b> Optional banner shown only in the main menu for a distinctive CLI look.</li>
</ul>

<hr/>

<h2>📦 Installation</h2>

```bash
git clone https://github.com/PRxKaiser/PacketBloom.git
cd packetbloom
g++ -O2 -shared -fPIC $(python3 -m pybind11 --includes) backend/packetbloom_backend.cpp -lpcap -o backend$(python3-config --extension-suffix)
```
<h2>🚀 Usage</h2>

sudo python3 core.py

```MENU
╔══════════════════════════════════════════════╗
║ [1] Analyze PCAP                            ║
║ [2] Save last result (JSON)                 ║
║ [3] Live Capture                            ║
║ [4] Exit                                    ║
╚══════════════════════════════════════════════╝
```
<h2>⚙️ Requirements</h2>
<ul>
<li>Python 3.8+</li>
<li>libpcap</li>
<li>pybind11</li>
<li>scapy</li>
<li>colorama</li>
</ul>

<hr/>

<h2>📜 License</h2>
<p>MIT License — free to use, modify, and distribute.</p>
<h1>educational use only</h1>
