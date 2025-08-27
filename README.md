<<<<<<< HEAD
# win-count-releases
อัพเดท Win Count by ArtYWoof Last
=======
# 👑 Win Count by ArtYWoof

A powerful and beautiful win counter application designed specifically for TikTok Live streamers. Features real-time overlay support, customizable hotkeys, and stunning visual effects.

![Win Count by ArtYWoof](https://img.shields.io/badge/Version-1.0.1-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)

## ✨ Features

### 🎯 Core Functionality
- **Real-time win counting** with instant overlay updates
- **Customizable hotkeys** (Alt+=, Alt+-, Alt+Shift+=, Alt+Shift+-)
- **Goal tracking** with visual progress indicators
- **Multiple presets** (up to 10) for different stream scenarios
- **Auto-save** functionality to preserve your progress

### 🎨 Visual & UX
- **Rainbow border effects** with smooth animations
- **Beautiful glass morphism** design
- **Customizable themes** and visual effects
- **Smooth animations** for all interactions
- **Professional UI/UX** optimized for streamers

### 🔧 Advanced Features
- **System tray integration** with enhanced menu
- **Auto-update system** with silent background updates
- **Overlay support** for TikTok Live Studio integration
- **Sound effects** with customizable audio files
- **Anti-tampering protection** for security

### 📱 System Integration
- **Minimize to taskbar** with smooth animations
- **Hide to system tray** with enhanced context menu
- **Always-on-top** functionality
- **Global hotkey support** (works even when minimized)

## 🚀 Quick Start

1. **Download** the latest version from [Releases](https://github.com/artywoof/win-count-by-artywoof/releases/latest)
2. **Install** the MSI file
3. **Launch** from Start Menu or Desktop shortcut
4. **Configure** your hotkeys in Settings
5. **Start streaming** with your TikTok Live!

## 🎮 Hotkeys

| Action | Default Hotkey | Description |
|--------|----------------|-------------|
| Increment | `Alt + =` | Add 1 to win count |
| Decrement | `Alt + -` | Subtract 1 from win count |
| Increment 10 | `Alt + Shift + =` | Add 10 to win count |
| Decrement 10 | `Alt + Shift + -` | Subtract 10 from win count |

## 🎨 Overlay Integration

1. **Copy overlay link** from the app
2. **Paste into TikTok Live Studio** as a browser source
3. **Enjoy real-time updates** during your stream!

## 📦 Installation

### System Requirements
- Windows 10/11 (64-bit)
- 4GB RAM minimum
- 100MB free disk space

### Installation Steps
1. Download the MSI installer
2. Run the installer as Administrator
3. Follow the installation wizard
4. Launch from Start Menu or Desktop shortcut

## 🔧 Configuration

### Presets
- Create up to 10 different presets
- Each preset saves win count, goal, and visibility settings
- Switch between presets instantly

### Settings
- **Hotkeys**: Customize all hotkey combinations
- **Sound**: Enable/disable sound effects, upload custom sounds
- **Overlay**: Configure overlay visibility and appearance
- **Updates**: Configure auto-update preferences

## 🛡️ Security Features

- **Anti-tampering protection** prevents unauthorized modifications
- **Machine-specific licensing** ensures legitimate usage
- **Encrypted data storage** for user preferences
- **Secure update system** with signature verification

## 🔄 Auto-Update System

The app automatically checks for updates and will:
- **Notify** you when updates are available
- **Download** updates in the background
- **Install** updates silently
- **Restart** the app with new features

## 🛠️ Development

### Tech Stack
- **Backend**: Tauri v2 (Rust)
- **Frontend**: Svelte, TypeScript, Tailwind CSS
- **Build/Package Manager**: Bun

### Development Setup
```bash
# Clone the repository
git clone https://github.com/artywoof/win-count-by-artywoof.git

# Install dependencies
bun install

# Start dev: Bun license server + Vite + Tauri app
bun run tauri dev

# Build frontend and Tauri app
bun run build

# Seed a test license (optional, dev only)
bun run dev:server & sleep 1 && bun run seed:license
```

### Folder Structure
```
win-count-by-artywoof/
  server/                # Bun license server (Bun.serve + bun:sqlite)
    index.ts
    license.db
  src/                   # SvelteKit frontend
    lib/
      audio/
      hotkeys/
      license/
      security/
      components/
      stores/
      index.ts           # central exports for $lib
    routes/
      app/+page.svelte   # main app UI
      overlay/+page.svelte
  src-tauri/             # Tauri (Rust)
    src/main.rs          # core app logic, licensing, security
    build.rs             # release-only obfuscation
    tauri.conf.json      # window, CSP, updater
```

### Scripts
- `bun run tauri dev`: Start Bun license server + Vite + Tauri app (dev)
- `bun run dev:server`: Start Bun license server only (hot reload)
- `bun run build`: Build Tauri app (release)
- `bun run build:frontend`: Build SvelteKit frontend
- `bun run build:server`: Bundle license server
- `bun run seed:license`: Seed TEST-123 license (dev)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**ArtYWoof** - TikTok Live Streamer & Developer

- 🎮 [TikTok](https://www.tiktok.com/@artywoof)
- 💻 [GitHub](https://github.com/artywoof)
- 📧 Contact: [your-email@example.com]

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📞 Support

If you encounter any issues or have questions:
1. Check the [Issues](https://github.com/artywoof/win-count-by-artywoof/issues) page
2. Create a new issue with detailed information
3. Contact the developer directly

---

**Made with ❤️ for the TikTok Live streaming community** 
>>>>>>> main-repo/main
