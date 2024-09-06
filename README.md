# Boot It

**Boot It** is an intuitive tool for creating bootable USB drives. Whether you're an IT pro or just looking to install a fresh OS, Boot It handles the technical details so you don't have to. One password per session, real-time USB detection, and a beautiful dark mode make it the go-to tool for booting bliss.

---

## Features

- **Session Password Management**: (Linux) Boot It requests your sudo password **only once** per session. No more interruptions!
- **Real-Time USB Detection**: USBs are automatically detected and updated without any manual refresh.
- **Dark Mode**: Dark mode is on by default. Switch it off if you're feeling the light-side vibes.
- **Detailed Progress Tracking**: Track progress in real-time with visual and textual feedback. No more guesswork!
- **Cross-Platform**: Compatible with both Linux and Windows, Boot It works across platforms seamlessly.

---

## Why Boot It?

### Simple Yet Powerful

Boot It is designed with everyone in mind. Whether you’re tech-savvy or not, its intuitive UI ensures you won’t get lost in complex processes.

### Password Simplicity (Linux)
Tired of entering your sudo password over and over again? We feel you! Boot It stores it securely for the session and lets you focus on the task at hand.

### Real-Time USB Detection
Once your bootable USB is ready, Boot It detects and updates it on the fly—no manual effort needed.

---

## Use Cases

### 1. **Operating System Installations**
Create bootable USBs for Windows, Linux, or any other OS quickly and painlessly.

### 2. **System Admins/IT Pros**
Managing several systems? Boot It helps with multiple USB creations, offering real-time progress updates and post-creation USB detection.

### 3. **Tech Enthusiasts**
Boot It is ideal for creating multi-purpose bootable drives with future support for multi-ISO boot coming soon!

---

## Tech Stack

Here’s what powers Boot It:

- **PyQt5**: Provides the polished and responsive user interface.
- **Subprocess Module**: Manages all the low-level system commands required for disk formatting and writing.
- **pyudev**: For real-time USB detection on Linux.
- **Logging**: Full logging of every step, stored in `boot_it.log`, for troubleshooting or tracking the process.
- **Cross-Platform**: Works on both Linux and Windows, handling OS-specific disk operations behind the scenes.

---

## Installation

### Linux
1. Clone the repo:
   ```bash
   git clone https://github.com/agustealo/boot-it.git
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the app:
   ```bash
   python3 main.py
   ```

### Windows
1. Clone the repo:
   ```bash
   git clone https://github.com/agustealo/boot-it.git
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the app:
   ```bash
   python main.py
   ```

---

## How to Use

1. **Launch Boot It**: Once you run the application, the main window will open.
2. **Select ISO**: Choose the ISO you want to burn to your USB.
3. **Choose USB**: Select the USB device you want to create the bootable drive on.
4. **Create Bootable USB**: Click the "Create Bootable USB" button, enter your password (Linux only), and let Boot It handle the rest!

---

## Roadmap

- **Multi-ISO Boot Support**: Coming soon, you'll be able to store multiple OS images on a single USB drive.
- **Advanced Error Diagnostics**: Adding enhanced error logs with troubleshooting recommendations.

---

## Contributing

We welcome contributions from anyone! Whether it's bug reports, feature requests, or pull requests, we'd love to collaborate with the community. Follow these steps to get started:

### Steps to Contribute:
1. Fork the repository.
2. Create a new branch (`git checkout -b feature/your-feature`).
3. Commit your changes (`git commit -m 'Add some feature'`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a pull request.

### Code of Conduct:
Please adhere to the [Contributor Covenant](https://www.contributor-covenant.org/) when interacting with others in this project.

---

## License

**Boot It** is licensed under the MIT License. See the [LICENSE](LICENSE) file for more information.

---

## Contributors

Boot It is made possible thanks to the contributions of the following awesome people:

- **Agustealo** – Initial development and overall project guidance.
- **Zeus Eternal** – Special adaptations
- **The Open-Source Community** – For bug reports, suggestions, and improvements.

---

## Support

For any questions, issues, or just to chat with the dev team, feel free to:
- Open an issue on GitHub.
- Reach out via [agustealo@gmail.com](mailto:agustealo@gmail.com).
  
We’re always happy to help!

---

## Conclusion

Boot It is designed to make your life easier. Whether you're creating bootable USBs for an OS installation or for your tech projects, Boot It offers ease of use, reliability, and a dash of fun. Get booting—fast and painless—with Boot It!
