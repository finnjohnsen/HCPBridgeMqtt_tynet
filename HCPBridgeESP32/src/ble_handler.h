#pragma once

#include <Arduino.h>
#include <NimBLEDevice.h>
#include <NimBLEServer.h>
#include <NimBLEUtils.h>
#include <Preferences.h>
#include <ArduinoJson.h>
#include <cstdlib>
#include "hoermann.h"
#include "configuration.h"
#include "preferences_handler.h"

// ============================================================================
// BLE Constants
// ============================================================================

#define BLE_SERVICE_UUID        "fb0a5c8e-9d21-4b6a-8c3f-1e7a0d4b5c6f"
#define BLE_CHAR_OPEN_UUID      "fb0a5c8e-9d21-4b6a-8c3f-1e7a0d4b5c70"
#define BLE_CHAR_CLOSE_UUID     "fb0a5c8e-9d21-4b6a-8c3f-1e7a0d4b5c71"
#define BLE_CHAR_STOP_UUID      "fb0a5c8e-9d21-4b6a-8c3f-1e7a0d4b5c72"
#define BLE_CHAR_TOGGLE_UUID    "fb0a5c8e-9d21-4b6a-8c3f-1e7a0d4b5c73"
#define BLE_CHAR_STATUS_UUID    "fb0a5c8e-9d21-4b6a-8c3f-1e7a0d4b5c74"
#define BLE_CHAR_AUTH_UUID      "fb0a5c8e-9d21-4b6a-8c3f-1e7a0d4b5c75"
#define BLE_CHAR_AUTH_STATUS_UUID "fb0a5c8e-9d21-4b6a-8c3f-1e7a0d4b5c76"

#define BLE_DEVICE_NAME         "HCPBridge"
#define BLE_MAX_USERS           8
#define BLE_MAX_LOG_ENTRIES     100
#define BLE_SALT_LENGTH         16
#define BLE_HASH_LENGTH         32
#define BLE_LOCKOUT_ATTEMPTS    5
#define BLE_LOCKOUT_DURATION_MS (30UL * 60 * 1000)

#define BLE_CMD_OPEN    0x01
#define BLE_CMD_CLOSE   0x02
#define BLE_CMD_STOP    0x03
#define BLE_CMD_TOGGLE  0x04

// ============================================================================
// Audit Log Entry (7 bytes)
// ============================================================================

struct BleLogEntry {
    uint8_t userId;
    uint8_t action;
    uint8_t result;
    uint32_t timestamp;
};

// ============================================================================
// NVS namespace
// ============================================================================

#define BLE_PREF_NAMESPACE "ble_hcp"

// ============================================================================
// Per-connection auth state
// ============================================================================

static bool bleConnAuthenticated = false;
static char bleConnUserId = 0;

// ============================================================================
// BLE Handler
// ============================================================================

class BleHandler {
public:
    void begin(Preferences* prefs);
    void loop();
    void notifyStatus();

    // User management
    bool addUser(char userId, const char* pin);
    bool removeUser(char userId);
    bool setUserPin(char userId, const char* pin);
    bool getUserEnabled(char userId);
    void setUserEnabled(char userId, bool enabled);
    bool getUserInfo(char userId, JsonObject& info);
    void initDefaultUsers();

    // Audit log
    void appendLog(char userId, uint8_t action, uint8_t result);
    void getAuditLog(JsonArray& entries);
    void clearAuditLog();

    // Lockout
    bool isLockedOut();
    unsigned long getLockoutRemainingMs();
    void triggerLockout();

    // Advertising
    bool isAdvertising() { return _advertising; }
    void startAdvertising();
    void stopAdvertising();

    // Called from BLE callbacks
    void handleAuth(const uint8_t* data, size_t len);
    void handleCommand(uint8_t cmd, char userId);
    void setAuthStatusValue(bool authenticated);

private:
    void setupServer();
    void loadUsers();
    void loadLog();
    void saveLog();

    Preferences _blePrefs;

    NimBLEServer* _server = nullptr;
    NimBLEService* _service = nullptr;
    NimBLECharacteristic* _charOpen = nullptr;
    NimBLECharacteristic* _charClose = nullptr;
    NimBLECharacteristic* _charStop = nullptr;
    NimBLECharacteristic* _charToggle = nullptr;
    NimBLECharacteristic* _charStatus = nullptr;
    NimBLECharacteristic* _charAuth = nullptr;
    NimBLECharacteristic* _charAuthStatus = nullptr;

    struct UserRecord {
        bool exists = false;
        bool enabled = false;
        char id = 0;
        uint8_t hash[BLE_HASH_LENGTH];
        uint8_t salt[BLE_SALT_LENGTH];
    } _users[BLE_MAX_USERS];

    BleLogEntry _log[BLE_MAX_LOG_ENTRIES] = {};
    size_t _logCount = 0;

    unsigned long _lockoutUntil = 0;
    uint8_t _failedAttempts = 0;

    bool _advertising = false;
};

// ============================================================================
// Global instance (defined in main.cpp)
// ============================================================================

extern BleHandler bleHandler;

// ============================================================================
// Connection callbacks
// ============================================================================

class BleConnectCallback : public NimBLEServerCallbacks {
public:
    void onConnect(NimBLEServer* pServer) override {
        bleConnAuthenticated = false;
        bleConnUserId = 0;
        bleHandler.setAuthStatusValue(false);
        DBG_PRINTLN("BLE client connected");
    }
    void onDisconnect(NimBLEServer* pServer) override {
        bleConnAuthenticated = false;
        bleConnUserId = 0;
        DBG_PRINTLN("BLE client disconnected");
        bleHandler.startAdvertising();
    }
};

// ============================================================================
// Characteristic callbacks
// ============================================================================

class BleCommandCallback : public NimBLECharacteristicCallbacks {
public:
    void onWrite(NimBLECharacteristic *pCharacteristic) override {
        std::string uuid = pCharacteristic->getUUID().toString();
        std::string data = pCharacteristic->getValue();

        if (uuid == BLE_CHAR_AUTH_UUID) {
            bleHandler.handleAuth((const uint8_t*)data.c_str(), data.length());
            return;
        }

        if (!bleConnAuthenticated) {
            DBG_PRINTLN("BLE: command rejected - not authenticated");
            return;
        }

        uint8_t cmd = 0;
        if (uuid == BLE_CHAR_OPEN_UUID) cmd = BLE_CMD_OPEN;
        else if (uuid == BLE_CHAR_CLOSE_UUID) cmd = BLE_CMD_CLOSE;
        else if (uuid == BLE_CHAR_STOP_UUID) cmd = BLE_CMD_STOP;
        else if (uuid == BLE_CHAR_TOGGLE_UUID) cmd = BLE_CMD_TOGGLE;

        if (cmd) {
            bleHandler.handleCommand(cmd, bleConnUserId);
        }
    }
};

class BleAuthStatusCallback : public NimBLECharacteristicCallbacks {
public:
    void onRead(NimBLECharacteristic *pCharacteristic) override {
        uint8_t val = bleConnAuthenticated ? 0x01 : 0x00;
        pCharacteristic->setValue(val);
    }
};

// ============================================================================
// SHA-256 via mbedtls (bundled with ESP-IDF)
// ============================================================================

extern "C" {
    #include "mbedtls/sha256.h"
}

static void computeHash(const char* pin, const uint8_t* salt, uint8_t* output) {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0);
    mbedtls_sha256_update_ret(&ctx, salt, BLE_SALT_LENGTH);
    mbedtls_sha256_update_ret(&ctx, (const uint8_t*)pin, strlen(pin));
    mbedtls_sha256_finish_ret(&ctx, output);
    mbedtls_sha256_free(&ctx);
}

// ============================================================================
// Implementation
// ============================================================================

void BleHandler::begin(Preferences* prefs) {
    _blePrefs.begin(BLE_PREF_NAMESPACE, false);

    loadUsers();
    loadLog();

    bool anyUser = false;
    for (int i = 0; i < BLE_MAX_USERS; i++) {
        if (_users[i].exists) { anyUser = true; break; }
    }
    if (!anyUser) {
        initDefaultUsers();
    }

    String bleName = prefs->getString(preference_hostname);
    NimBLEDevice::init(bleName.c_str());

    _server = NimBLEDevice::createServer();
    _server->setCallbacks(new BleConnectCallback());

    setupServer();
    startAdvertising();

    DBG_PRINTLN("BLE server initialized");
}

void BleHandler::setupServer() {
    _service = _server->createService(BLE_SERVICE_UUID);

    _charOpen = _service->createCharacteristic(BLE_CHAR_OPEN_UUID, NIMBLE_PROPERTY::WRITE);
    _charOpen->setCallbacks(new BleCommandCallback());

    _charClose = _service->createCharacteristic(BLE_CHAR_CLOSE_UUID, NIMBLE_PROPERTY::WRITE);
    _charClose->setCallbacks(new BleCommandCallback());

    _charStop = _service->createCharacteristic(BLE_CHAR_STOP_UUID, NIMBLE_PROPERTY::WRITE);
    _charStop->setCallbacks(new BleCommandCallback());

    _charToggle = _service->createCharacteristic(BLE_CHAR_TOGGLE_UUID, NIMBLE_PROPERTY::WRITE);
    _charToggle->setCallbacks(new BleCommandCallback());

    _charStatus = _service->createCharacteristic(BLE_CHAR_STATUS_UUID, NIMBLE_PROPERTY::NOTIFY);

    _charAuth = _service->createCharacteristic(BLE_CHAR_AUTH_UUID, NIMBLE_PROPERTY::WRITE);
    _charAuth->setCallbacks(new BleCommandCallback());

    // Auth status — read 0x00 (not auth) or 0x01 (authenticated)
    _charAuthStatus = _service->createCharacteristic(BLE_CHAR_AUTH_STATUS_UUID, NIMBLE_PROPERTY::READ);
    _charAuthStatus->setCallbacks(new BleAuthStatusCallback());
    _charAuthStatus->setValue(0);

    _service->start();
}

void BleHandler::startAdvertising() {
    if (_advertising) return;
    NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
    adv->addServiceUUID(BLE_SERVICE_UUID);
    adv->setScanResponse(true);
    adv->setMinPreferred(0x06);
    adv->setMaxPreferred(0x12);
    NimBLEDevice::startAdvertising();
    _advertising = true;
    DBG_PRINTLN("BLE advertising started");
}

void BleHandler::stopAdvertising() {
    NimBLEDevice::stopAdvertising();
    _advertising = false;
    DBG_PRINTLN("BLE advertising stopped");
}

void BleHandler::handleAuth(const uint8_t* data, size_t len) {
    if (isLockedOut()) {
        DBG_PRINTLN("BLE: locked out, auth rejected");
        return;
    }

    JsonDocument doc;
    DeserializationError err = deserializeJson(doc, data, len);
    if (err) {
        DBG_PRINTLN("BLE auth: invalid JSON");
        return;
    }

    String userStr = doc["user"].as<String>();
    String pin = doc["pin"].as<String>();

    if (userStr.length() != 1 || pin.length() < 1) {
        DBG_PRINTLN("BLE auth: invalid format");
        _failedAttempts++;
        if (_failedAttempts >= BLE_LOCKOUT_ATTEMPTS) triggerLockout();
        return;
    }

    char userId = userStr[0];
    int idx = userId - 'A';

    if (idx < 0 || idx >= BLE_MAX_USERS || !_users[idx].exists || !_users[idx].enabled) {
        DBG_PRINT("BLE auth: user "); DBG_PRINT(userId); DBG_PRINTLN(" invalid/disabled");
        _failedAttempts++;
        if (_failedAttempts >= BLE_LOCKOUT_ATTEMPTS) triggerLockout();
        return;
    }

    uint8_t computed[BLE_HASH_LENGTH];
    computeHash(pin.c_str(), _users[idx].salt, computed);

    if (memcmp(computed, _users[idx].hash, BLE_HASH_LENGTH) == 0) {
        bleConnAuthenticated = true;
        bleConnUserId = userId;
        _failedAttempts = 0;
        setAuthStatusValue(true);
        DBG_PRINT("BLE auth OK: user "); DBG_PRINTLN(userId);
    } else {
        DBG_PRINT("BLE auth FAIL: user "); DBG_PRINTLN(userId);
        _failedAttempts++;
        if (_failedAttempts >= BLE_LOCKOUT_ATTEMPTS) triggerLockout();
    }
}

void BleHandler::handleCommand(uint8_t cmd, char userId) {
    DBG_PRINT("BLE cmd: user="); DBG_PRINT(userId); DBG_PRINT(" cmd="); DBG_PRINTLN(cmd);

    uint8_t result = 0;

    switch (cmd) {
        case BLE_CMD_OPEN:   hoermannEngine->openDoor();   break;
        case BLE_CMD_CLOSE:  hoermannEngine->closeDoor();  break;
        case BLE_CMD_STOP:   hoermannEngine->stopDoor();   break;
        case BLE_CMD_TOGGLE: hoermannEngine->toogleDoor(); break;
        default:             result = 1; break;
    }

    appendLog(userId, cmd, result);
    notifyStatus();
}

void BleHandler::notifyStatus() {
    if (!_charStatus) return;

    JsonDocument doc;
    doc["state"] = hoermannEngine->state->translatedState;
    doc["current"] = (int)(hoermannEngine->state->currentPosition * 100);
    doc["target"] = (int)(hoermannEngine->state->targetPosition * 100);
    doc["light"] = hoermannEngine->state->lightOn;
    doc["auth"] = bleConnAuthenticated;

    std::string json;
    serializeJson(doc, json);
    _charStatus->setValue((const uint8_t*)json.c_str(), json.length());
    _charStatus->notify();
}

// ---- User Management ----

void BleHandler::loadUsers() {
    for (int i = 0; i < BLE_MAX_USERS; i++) {
        char id = 'A' + i;
        char key[8];
        snprintf(key, sizeof(key), "u%c_ex", id);

        if (!_blePrefs.getBool(key, false)) {
            _users[i].exists = false;
            _users[i].enabled = false;
            continue;
        }

        _users[i].exists = true;
        _users[i].id = id;

        snprintf(key, sizeof(key), "u%c_en", id);
        _users[i].enabled = _blePrefs.getBool(key, true);

        snprintf(key, sizeof(key), "u%c_hash", id);
        _blePrefs.getBytes(key, _users[i].hash, BLE_HASH_LENGTH);

        snprintf(key, sizeof(key), "u%c_salt", id);
        _blePrefs.getBytes(key, _users[i].salt, BLE_SALT_LENGTH);
    }
}

void BleHandler::initDefaultUsers() {
    struct { char id; const char* pin; } defaults[] = {
        {'A', "A001BLE"}, {'B', "B002BLE"}, {'C', "C003BLE"}, {'D', "D004BLE"},
        {'E', "E005BLE"}, {'F', "F006BLE"}, {'G', "G007BLE"}, {'H', "H008BLE"}
    };

    for (int i = 0; i < BLE_MAX_USERS; i++) {
        addUser(defaults[i].id, defaults[i].pin);
    }
    DBG_PRINTLN("BLE: 8 default users created");
}

bool BleHandler::addUser(char userId, const char* pin) {
    int idx = userId - 'A';
    if (idx < 0 || idx >= BLE_MAX_USERS) return false;

    uint8_t salt[BLE_SALT_LENGTH];
    for (int i = 0; i < BLE_SALT_LENGTH; i++) salt[i] = rand() % 256;

    uint8_t hash[BLE_HASH_LENGTH];
    computeHash(pin, salt, hash);

    _users[idx].exists = true;
    _users[idx].id = userId;
    _users[idx].enabled = true;
    memcpy(_users[idx].hash, hash, BLE_HASH_LENGTH);
    memcpy(_users[idx].salt, salt, BLE_SALT_LENGTH);

    char key[8];
    snprintf(key, sizeof(key), "u%c_ex", userId); _blePrefs.putBool(key, true);
    snprintf(key, sizeof(key), "u%c_en", userId); _blePrefs.putBool(key, true);
    snprintf(key, sizeof(key), "u%c_hash", userId); _blePrefs.putBytes(key, hash, BLE_HASH_LENGTH);
    snprintf(key, sizeof(key), "u%c_salt", userId); _blePrefs.putBytes(key, salt, BLE_SALT_LENGTH);

    DBG_PRINT("BLE: added user "); DBG_PRINTLN(userId);
    return true;
}

bool BleHandler::removeUser(char userId) {
    int idx = userId - 'A';
    if (idx < 0 || idx >= BLE_MAX_USERS) return false;

    char key[8];
    snprintf(key, sizeof(key), "u%c_ex", userId); _blePrefs.remove(key);
    snprintf(key, sizeof(key), "u%c_en", userId); _blePrefs.remove(key);
    snprintf(key, sizeof(key), "u%c_hash", userId); _blePrefs.remove(key);
    snprintf(key, sizeof(key), "u%c_salt", userId); _blePrefs.remove(key);

    _users[idx].exists = false;
    _users[idx].enabled = false;
    _users[idx].id = 0;

    DBG_PRINT("BLE: removed user "); DBG_PRINTLN(userId);
    return true;
}

bool BleHandler::setUserPin(char userId, const char* pin) {
    int idx = userId - 'A';
    if (idx < 0 || idx >= BLE_MAX_USERS || !_users[idx].exists) return false;

    uint8_t hash[BLE_HASH_LENGTH];
    computeHash(pin, _users[idx].salt, hash);
    memcpy(_users[idx].hash, hash, BLE_HASH_LENGTH);

    char key[8];
    snprintf(key, sizeof(key), "u%c_hash", userId);
    _blePrefs.putBytes(key, hash, BLE_HASH_LENGTH);

    DBG_PRINT("BLE: updated PIN for "); DBG_PRINTLN(userId);
    return true;
}

bool BleHandler::getUserEnabled(char userId) {
    int idx = userId - 'A';
    if (idx < 0 || idx >= BLE_MAX_USERS) return false;
    return _users[idx].enabled;
}

void BleHandler::setUserEnabled(char userId, bool enabled) {
    int idx = userId - 'A';
    if (idx < 0 || idx >= BLE_MAX_USERS) return;

    _users[idx].enabled = enabled;
    char key[8];
    snprintf(key, sizeof(key), "u%c_en", userId);
    _blePrefs.putBool(key, enabled);
}

bool BleHandler::getUserInfo(char userId, JsonObject& info) {
    int idx = userId - 'A';
    if (idx < 0 || idx >= BLE_MAX_USERS || !_users[idx].exists) return false;
    info["id"] = String(_users[idx].id);
    info["enabled"] = _users[idx].enabled;
    return true;
}

// ---- Audit Log ----

void BleHandler::loadLog() {
    _logCount = _blePrefs.getUShort("log_cnt", 0);
    if (_logCount == 0) return;

    size_t blobSize = _logCount * sizeof(BleLogEntry);
    if (blobSize > BLE_MAX_LOG_ENTRIES * sizeof(BleLogEntry)) {
        blobSize = BLE_MAX_LOG_ENTRIES * sizeof(BleLogEntry);
        _logCount = BLE_MAX_LOG_ENTRIES;
    }
    _blePrefs.getBytes("log_data", _log, blobSize);
}

void BleHandler::saveLog() {
    _blePrefs.putUShort("log_cnt", (uint16_t)_logCount);
    if (_logCount > 0) {
        _blePrefs.putBytes("log_data", _log, _logCount * sizeof(BleLogEntry));
    }
}

void BleHandler::appendLog(char userId, uint8_t action, uint8_t result) {
    if (_logCount >= BLE_MAX_LOG_ENTRIES) {
        memmove(&_log[0], &_log[1], (_logCount - 1) * sizeof(BleLogEntry));
        _logCount--;
    }

    _log[_logCount].userId = userId;
    _log[_logCount].action = action;
    _log[_logCount].result = result;
    _log[_logCount].timestamp = millis();
    _logCount++;

    saveLog();
}

void BleHandler::getAuditLog(JsonArray& entries) {
    for (int i = (int)_logCount - 1; i >= 0; i--) {
        JsonObject entry = entries.add<JsonObject>();
        entry["user"] = String((char)_log[i].userId);

        switch (_log[i].action) {
            case BLE_CMD_OPEN:   entry["action"] = "open";   break;
            case BLE_CMD_CLOSE:  entry["action"] = "close";  break;
            case BLE_CMD_STOP:   entry["action"] = "stop";   break;
            case BLE_CMD_TOGGLE: entry["action"] = "toggle"; break;
            default:             entry["action"] = "unknown"; break;
        }

        entry["result"] = _log[i].result == 0 ? "ok" : "failed";
        entry["ts"] = _log[i].timestamp;
    }
}

void BleHandler::clearAuditLog() {
    _logCount = 0;
    memset(_log, 0, sizeof(_log));
    saveLog();
}

// ---- Lockout ----

void BleHandler::triggerLockout() {
    _lockoutUntil = millis() + BLE_LOCKOUT_DURATION_MS;
    _failedAttempts = 0;
    DBG_PRINTLN("BLE: lockout activated (30 min)");
}

bool BleHandler::isLockedOut() {
    if (_lockoutUntil == 0) return false;
    if ((long)(millis() - _lockoutUntil) >= 0) {
        _lockoutUntil = 0;
        _failedAttempts = 0;
        return false;
    }
    return true;
}

unsigned long BleHandler::getLockoutRemainingMs() {
    if (!isLockedOut()) return 0;
    return (unsigned long)(_lockoutUntil - millis());
}

// ---- Loop ----

void BleHandler::setAuthStatusValue(bool authenticated) {
    if (_charAuthStatus) {
        _charAuthStatus->setValue(authenticated ? 1 : 0);
        _charAuthStatus->notify();
    }
}

void BleHandler::loop() {
    // BLE stack handled by NimBLE internally
}
