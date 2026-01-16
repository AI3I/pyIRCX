/**
 * pyIRCX WebChat Configuration
 *
 * This file contains all configurable parameters for the webchat client.
 * Edit these values to customize your webchat deployment.
 *
 * After making changes, restart your web server to apply them.
 */

const WEBCHAT_CONFIG = {
    /**
     * WebSocket Connection
     * ====================
     * The gateway URL is auto-detected based on protocol, but you can override it here.
     * Leave as null for auto-detection.
     *
     * Auto-detection:
     *   - HTTP:  ws://hostname:8765 (direct connection)
     *   - HTTPS: wss://hostname/ws (via reverse proxy)
     */
    websocketUrl: null,  // null = auto-detect, or set explicit URL like 'ws://localhost:8765'

    /**
     * WebSocket Port (for auto-detection on HTTP)
     * This should match the WS_PORT in /etc/pyircx/webchat.conf
     */
    websocketPort: 8765,

    /**
     * WebSocket Path (for auto-detection on HTTPS via reverse proxy)
     */
    websocketPath: '/ws',

    /**
     * Default Channel
     * The channel users join by default when connecting
     */
    defaultChannel: '#pyIRCX',

    /**
     * Default Nickname
     * Leave empty for user to choose, or set a prefix/default
     */
    defaultNick: '',

    /**
     * Performance Tuning
     * ==================
     */
    whoThrottleMs: 2000,      // Minimum milliseconds between WHO requests per channel
    commandDelayMs: 600,      // Delay between queued commands (prevents flooding)

    /**
     * UI Configuration
     * ================
     */
    maxHistoryLines: 1000,    // Maximum lines to keep in channel history (per channel)
    timestampFormat: 'auto',  // 'auto' uses user's 12/24hr preference, or '12hr'/'24hr'

    /**
     * Notification Settings
     * =====================
     */
    enableDesktopNotifications: true,   // Ask for desktop notification permission
    notifyOnPrivateMessage: true,       // Desktop notification for private messages
    notifyOnMention: true,              // Desktop notification when your nick is mentioned
    notifyOnInvite: true,               // Desktop notification for channel invites

    /**
     * Sound Effects
     * =============
     */
    enableSounds: true,                 // Enable sound effects
    soundOnPrivateMessage: true,        // Sound when receiving private message
    soundOnMention: true,               // Sound when mentioned in channel
    soundVolume: 0.3,                   // Volume (0.0 to 1.0)

    /**
     * Staff Emoji/Icons
     * =================
     * Customize the emoji shown for each staff level
     */
    staffEmoji: {
        'SERVICE': '🤖',
        'ADMIN': '👑',
        'SYSOP': '🏅',
        'GUIDE': '🔰'
    },

    /**
     * Channel Mode Emoji/Icons
     * ========================
     */
    modeEmoji: {
        'owner': '.',      // Owner prefix
        'host': '@',       // Host/Op prefix
        'voice': '+'       // Voice prefix
    },

    /**
     * Theme Settings
     * ==============
     */
    defaultTheme: 'auto',    // 'light', 'dark', or 'auto' (follows system preference)

    /**
     * Advanced Settings
     * =================
     */
    debugMode: false,        // Enable console logging for debugging
    autoReconnect: true,     // Automatically reconnect on disconnect
    reconnectDelayMs: 5000,  // Delay before attempting reconnect

    /**
     * Branding
     * ========
     */
    appTitle: 'pyIRCX WebChat',
    appIcon: 'favicon.svg',

    /**
     * Server Information Display
     * ==========================
     */
    showServerInfo: true,    // Show server info messages (004/005 numerics)
    showUnhandledNumerics: false  // Show unhandled numeric messages in status window
};

/**
 * Get the WebSocket URL based on configuration and auto-detection
 */
function getWebSocketUrl() {
    // If explicit URL is configured, use it
    if (WEBCHAT_CONFIG.websocketUrl) {
        return WEBCHAT_CONFIG.websocketUrl;
    }

    // Auto-detect based on protocol
    if (window.location.protocol === 'https:') {
        // HTTPS: Use wss:// with configured path (via reverse proxy)
        return `wss://${window.location.host}${WEBCHAT_CONFIG.websocketPath}`;
    } else {
        // HTTP: Use ws:// with configured port (direct connection)
        return `ws://${window.location.hostname}:${WEBCHAT_CONFIG.websocketPort}`;
    }
}
