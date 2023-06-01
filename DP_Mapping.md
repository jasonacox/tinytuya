# Tuya Cloud - Changing the Control Instruction Mode

DPS to Name mappings are now downloaded with devices.json starting with TinyTuya v1.12.8.  If this DPS mapping is not correct then you will need to change the Control Instruction Mode to DP Instruction Mode.

## How to get the full DPS mapping from Tuya Cloud.

This how-to will show you how to activate “DP Instruction” mode for your Tuya devices when using Tuya Cloud to pull data.  This will result in getting the full list of DPS values and their properties for your devices.

### Step 1 - Log in to your account on [iot.tuya.com](iot.tuya.com)

### Step 2 - Navigate to "Cloud" -> "Development" then select your project.

### Step 3 - Select "Devices" tab.

<img width="756" alt="image" src="https://user-images.githubusercontent.com/836718/218344965-8f6cd378-d8fd-4e46-b35e-5e2ba2d3a9d4.png">

### Step 4- Select the device types and click the the "pencil icon" to edit. 

<img width="753" alt="image" src="https://user-images.githubusercontent.com/836718/218361449-f8c03832-8be3-4b25-b2cd-223dc2c89923.png">

### Step 5 - Select the "DP Instruction" box and "Save Configuration"

<img width="757" alt="image" src="https://user-images.githubusercontent.com/836718/218344985-41183289-ee0e-4484-aa8d-7489fc3a9f15.png">

There doesn't appear to be a way to globally set "DP Instruction" for all device types.  You will need to select each device type and repeat the above step.

### Step 6 - Use TinyTuya to access the full set of DPS

After 12-24 hours, you should now be able to poll the Tuya Cloud using TinyTuya to get the full list of DPS properties and values.  Simply delete `devices.json` and re-run the Wizard.
