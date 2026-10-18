// Derived from the HomeKit ADK Lightbulb example (Apache-2.0); see hap_db.h for the license header.
#include "thermostat_db.h"

#include "accessory.h"
#include "config.h"
#include "hap_db.h"
#include "thermostat.h"

#define kIID_Thermostat               (HAP_DB_APP_IID_BASE + 0x00)
#define kIID_ThermostatSignature      (HAP_DB_APP_IID_BASE + 0x01)
#define kIID_ThermostatName           (HAP_DB_APP_IID_BASE + 0x02)
#define kIID_ThermostatCurrentState   (HAP_DB_APP_IID_BASE + 0x03)
#define kIID_ThermostatTargetState    (HAP_DB_APP_IID_BASE + 0x04)
#define kIID_ThermostatCurrentTemp    (HAP_DB_APP_IID_BASE + 0x05)
#define kIID_ThermostatTargetTemp     (HAP_DB_APP_IID_BASE + 0x06)
#define kIID_ThermostatDisplayUnits   (HAP_DB_APP_IID_BASE + 0x07)
#define kIID_ChildLock                (HAP_DB_APP_IID_BASE + 0x10)
#define kIID_ChildLockSignature       (HAP_DB_APP_IID_BASE + 0x11)
#define kIID_ChildLockName            (HAP_DB_APP_IID_BASE + 0x12)
#define kIID_ChildLockOn              (HAP_DB_APP_IID_BASE + 0x13)

#define DB_PROPS_RW_EV DB_PROPS(true, true, true, false)
#define DB_PROPS_R_EV  DB_PROPS(true, false, true, false)

#define SIGNATURE(var, iidv) \
    static const HAPDataCharacteristic var = { \
        .format = kHAPCharacteristicFormat_Data, \
        .iid = iidv, \
        .characteristicType = &kHAPCharacteristicType_ServiceSignature, \
        .debugDescription = kHAPCharacteristicDebugDescription_ServiceSignature, \
        .manufacturerDescription = NULL, \
        .properties = DB_PROPS_READ_CP, \
        .constraints = { .maxLength = 2097152 }, \
        .callbacks = { .handleRead = HAPHandleServiceSignatureRead, .handleWrite = NULL } \
    }

#define NAME(var, iidv) \
    static const HAPStringCharacteristic var = { \
        .format = kHAPCharacteristicFormat_String, \
        .iid = iidv, \
        .characteristicType = &kHAPCharacteristicType_Name, \
        .debugDescription = kHAPCharacteristicDebugDescription_Name, \
        .manufacturerDescription = NULL, \
        .properties = DB_PROPS_READ, \
        .constraints = { .maxLength = 64 }, \
        .callbacks = { .handleRead = HAPHandleNameRead, .handleWrite = NULL } \
    }

static float Celsius(int32_t tenths) {
    return (float) tenths / 10.0f;
}

// ----- Handlers

static HAPError ReadCurrentState(
        HAPAccessoryServerRef* server HAP_UNUSED,
        const HAPUInt8CharacteristicReadRequest* request HAP_UNUSED,
        uint8_t* value,
        void* _Nullable context HAP_UNUSED) {
    *value = thermo_current_state(thermostat_model());
    return kHAPError_None;
}

static HAPError ReadTargetState(
        HAPAccessoryServerRef* server HAP_UNUSED,
        const HAPUInt8CharacteristicReadRequest* request HAP_UNUSED,
        uint8_t* value,
        void* _Nullable context HAP_UNUSED) {
    *value = thermo_target_state(thermostat_model());
    return kHAPError_None;
}

static HAPError WriteTargetState(
        HAPAccessoryServerRef* server,
        const HAPUInt8CharacteristicWriteRequest* request HAP_UNUSED,
        uint8_t value,
        void* _Nullable context HAP_UNUSED) {
    HAPLogInfo(&kHAPLog_Default, "HomeKit: target state %u", value);
    if (!thermostat_set_target_state(value)) {
        return kHAPError_InvalidData;
    }
    thermostat_db_raise_events(server);
    return kHAPError_None;
}

static HAPError ReadCurrentTemp(
        HAPAccessoryServerRef* server HAP_UNUSED,
        const HAPFloatCharacteristicReadRequest* request HAP_UNUSED,
        float* value,
        void* _Nullable context HAP_UNUSED) {
    *value = Celsius(thermo_current_tenths(thermostat_model()));
    return kHAPError_None;
}

static HAPError ReadTargetTemp(
        HAPAccessoryServerRef* server HAP_UNUSED,
        const HAPFloatCharacteristicReadRequest* request HAP_UNUSED,
        float* value,
        void* _Nullable context HAP_UNUSED) {
    *value = Celsius(thermo_target_tenths(thermostat_model()));
    return kHAPError_None;
}

static HAPError WriteTargetTemp(
        HAPAccessoryServerRef* server,
        const HAPFloatCharacteristicWriteRequest* request HAP_UNUSED,
        float value,
        void* _Nullable context HAP_UNUSED) {
    HAPLogInfo(&kHAPLog_Default, "HomeKit: target %d.%d C", (int) value, (int) (value * 10) % 10);
    if (!thermostat_set_target_c(value)) {
        return kHAPError_InvalidData;
    }
    thermostat_db_raise_events(server);
    return kHAPError_None;
}

// The unit's own °C/°F display setting is left alone: HomeKit shows Celsius, writes are accepted
// and ignored (Home converts on the phone).
static HAPError ReadDisplayUnits(
        HAPAccessoryServerRef* server HAP_UNUSED,
        const HAPUInt8CharacteristicReadRequest* request HAP_UNUSED,
        uint8_t* value,
        void* _Nullable context HAP_UNUSED) {
    *value = kHAPCharacteristicValue_TemperatureDisplayUnits_Celsius;
    return kHAPError_None;
}

static HAPError WriteDisplayUnits(
        HAPAccessoryServerRef* server,
        const HAPUInt8CharacteristicWriteRequest* request,
        uint8_t value HAP_UNUSED,
        void* _Nullable context HAP_UNUSED) {
    HAPAccessoryServerRaiseEvent(server, request->characteristic, request->service, request->accessory);
    return kHAPError_None;
}

static HAPError ReadLock(
        HAPAccessoryServerRef* server HAP_UNUSED,
        const HAPBoolCharacteristicReadRequest* request HAP_UNUSED,
        bool* value,
        void* _Nullable context HAP_UNUSED) {
    *value = thermo_locked(thermostat_model());
    return kHAPError_None;
}

static HAPError WriteLock(
        HAPAccessoryServerRef* server,
        const HAPBoolCharacteristicWriteRequest* request HAP_UNUSED,
        bool value,
        void* _Nullable context HAP_UNUSED) {
    HAPLogInfo(&kHAPLog_Default, "HomeKit: child lock %s", value ? "on" : "off");
    thermostat_set_locked(value);
    thermostat_db_raise_events(server);
    return kHAPError_None;
}

// ----- Thermostat service

SIGNATURE(thermostatSignature, kIID_ThermostatSignature);
NAME(thermostatName, kIID_ThermostatName);

static const uint8_t kOff = kHAPCharacteristicValue_TargetHeatingCoolingState_Off;
static const uint8_t kHeat = kHAPCharacteristicValue_TargetHeatingCoolingState_Heat;
static const uint8_t kAuto = kHAPCharacteristicValue_TargetHeatingCoolingState_Auto;

static const HAPUInt8Characteristic currentState = {
    .format = kHAPCharacteristicFormat_UInt8,
    .iid = kIID_ThermostatCurrentState,
    .characteristicType = &kHAPCharacteristicType_CurrentHeatingCoolingState,
    .debugDescription = kHAPCharacteristicDebugDescription_CurrentHeatingCoolingState,
    .manufacturerDescription = NULL,
    .properties = DB_PROPS_R_EV,
    .units = kHAPCharacteristicUnits_None,
    .constraints = { .minimumValue = 0,
                     .maximumValue = 1,
                     .stepValue = 1,
                     .validValues = (const uint8_t* const[]) { &kOff, &kHeat, NULL } },
    .callbacks = { .handleRead = ReadCurrentState, .handleWrite = NULL }
};

static const HAPUInt8Characteristic targetState = {
    .format = kHAPCharacteristicFormat_UInt8,
    .iid = kIID_ThermostatTargetState,
    .characteristicType = &kHAPCharacteristicType_TargetHeatingCoolingState,
    .debugDescription = kHAPCharacteristicDebugDescription_TargetHeatingCoolingState,
    .manufacturerDescription = NULL,
    .properties = DB_PROPS_RW_EV,
    .units = kHAPCharacteristicUnits_None,
    .constraints = { .minimumValue = 0,
                     .maximumValue = 3,
                     .stepValue = 1,
                     .validValues = (const uint8_t* const[]) { &kOff, &kHeat, &kAuto, NULL } },
    .callbacks = { .handleRead = ReadTargetState, .handleWrite = WriteTargetState }
};

static const HAPFloatCharacteristic currentTemp = {
    .format = kHAPCharacteristicFormat_Float,
    .iid = kIID_ThermostatCurrentTemp,
    .characteristicType = &kHAPCharacteristicType_CurrentTemperature,
    .debugDescription = kHAPCharacteristicDebugDescription_CurrentTemperature,
    .manufacturerDescription = NULL,
    .properties = DB_PROPS_R_EV,
    .units = kHAPCharacteristicUnits_Celsius,
    .constraints = { .minimumValue = -20, .maximumValue = 100, .stepValue = 0.1f },
    .callbacks = { .handleRead = ReadCurrentTemp, .handleWrite = NULL }
};

static const HAPFloatCharacteristic targetTemp = {
    .format = kHAPCharacteristicFormat_Float,
    .iid = kIID_ThermostatTargetTemp,
    .characteristicType = &kHAPCharacteristicType_TargetTemperature,
    .debugDescription = kHAPCharacteristicDebugDescription_TargetTemperature,
    .manufacturerDescription = NULL,
    .properties = DB_PROPS_RW_EV,
    .units = kHAPCharacteristicUnits_Celsius,
    .constraints = { .minimumValue = THERMO_SET_MIN / 10.0f,
                     .maximumValue = THERMO_SET_MAX / 10.0f,
                     .stepValue = 0.5f },
    .callbacks = { .handleRead = ReadTargetTemp, .handleWrite = WriteTargetTemp }
};

static const HAPUInt8Characteristic displayUnits = {
    .format = kHAPCharacteristicFormat_UInt8,
    .iid = kIID_ThermostatDisplayUnits,
    .characteristicType = &kHAPCharacteristicType_TemperatureDisplayUnits,
    .debugDescription = kHAPCharacteristicDebugDescription_TemperatureDisplayUnits,
    .manufacturerDescription = NULL,
    .properties = DB_PROPS_RW_EV,
    .units = kHAPCharacteristicUnits_None,
    .constraints = { .minimumValue = 0, .maximumValue = 1, .stepValue = 1 },
    .callbacks = { .handleRead = ReadDisplayUnits, .handleWrite = WriteDisplayUnits }
};

const HAPService thermostatService = {
    .iid = kIID_Thermostat,
    .serviceType = &kHAPServiceType_Thermostat,
    .debugDescription = kHAPServiceDebugDescription_Thermostat,
    .name = THERMOSTAT_NAME,
    .properties = { .primaryService = true, .hidden = false, .ble = { .supportsConfiguration = false } },
    .linkedServices = NULL,
    .characteristics = (const HAPCharacteristic* const[]) { &thermostatSignature, &thermostatName,
                                                            &currentState, &targetState,
                                                            &currentTemp, &targetTemp,
                                                            &displayUnits, NULL }
};

// ----- Child lock (the unit's key lock, DP108)

SIGNATURE(childLockSignature, kIID_ChildLockSignature);
NAME(childLockName, kIID_ChildLockName);

static const HAPBoolCharacteristic childLockOn = {
    .format = kHAPCharacteristicFormat_Bool,
    .iid = kIID_ChildLockOn,
    .characteristicType = &kHAPCharacteristicType_On,
    .debugDescription = kHAPCharacteristicDebugDescription_On,
    .manufacturerDescription = NULL,
    .properties = DB_PROPS_RW_EV,
    .callbacks = { .handleRead = ReadLock, .handleWrite = WriteLock }
};

const HAPService childLockService = {
    .iid = kIID_ChildLock,
    .serviceType = &kHAPServiceType_Switch,
    .debugDescription = kHAPServiceDebugDescription_Switch,
    .name = "Child Lock",
    .properties = { .primaryService = false, .hidden = false, .ble = { .supportsConfiguration = false } },
    .linkedServices = NULL,
    .characteristics = (const HAPCharacteristic* const[]) { &childLockSignature, &childLockName, &childLockOn, NULL }
};

void thermostat_db_raise_events(HAPAccessoryServerRef* server) {
    const HAPAccessory* a = accessory_get();
    static const HAPCharacteristic* const kThermostat[] = { &currentState, &targetState, &currentTemp, &targetTemp };
    for (size_t i = 0; i < HAPArrayCount(kThermostat); i++) {
        HAPAccessoryServerRaiseEvent(server, kThermostat[i], &thermostatService, a);
    }
    HAPAccessoryServerRaiseEvent(server, &childLockOn, &childLockService, a);
}
