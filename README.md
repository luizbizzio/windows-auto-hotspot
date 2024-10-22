
# Windows Auto Hotspot 🚀

**Windows Auto Hotspot** is a PowerShell script that automatically manages your PC's **Wi-Fi hotspot**. It enables the hotspot when an Ethernet cable is connected (including via USB adapters) and disables it when disconnected. Follow the steps below to configure and automate the process using **Task Scheduler**.

## Step-by-Step Instructions 🖥️

### 1. Configure Your Wi-Fi Hotspot

Before using the script, you need to manually configure your Wi-Fi hotspot settings on Windows:

1. **Open Hotspot Settings**:
   - Go to **Settings > Network & Internet > Mobile Hotspot**.
   
   ![Hotspot Settings](./Hotspot%20Settings.png)

2. **Set the SSID and Password**:
   - Choose your **Network Name (SSID)** and **Password**.
   
   ![Edit Network Info](./Network%20Info.png)

3. **Select the Connection Type**:
   - If your device supports it, select between **2.4GHz** and **5GHz** for your Wi-Fi hotspot.
4. **Enable Internet Sharing**:
   - Set **Share my Internet connection** to **Wi-Fi**.

Once your hotspot is configured, you can move on to the next steps.

### 2. Download and Place the Script

1. Download the **Windows Auto Hotspot** script from this repository.
2. Place the script in a directory of your choice. It is recommended to save it in your **user's folder** (e.g., `C:\Users\YourUser\Documents`) or any easily accessible folder.

### 3. Set Up Task Scheduler

Now, let's automate the script using **Task Scheduler**:

1. **Open Task Scheduler**:
   - Search for **Task Scheduler** in the Windows Start menu and open it.
   
   ![Create Task](./Create%20Task.png)

2. **Create a New Task**:
   - Click on **Create Task** in the right sidebar.
   - Name the task something like "Windows Auto Hotspot".
   - Check **Run whether user is logged on or not** and **Do not store password**.
   - Check **Run with highest privileges**.
   
   ![General Settings](./General.png)

### 4. Configure the Triggers

1. **Create a Trigger**:
   - Go to the **Triggers** tab and click **New**.
   - Set **Begin the task** to **At startup**.
   - Under **Advanced settings**, check **Repeat task every** 5 minutes, and set the duration to **Indefinitely**.
   - Make sure the **Enabled** box is checked.
   
   ![New Trigger](./New%20Trigger.png)

### 5. Configure the Actions

1. **Set Action to Start PowerShell**:
   - Go to the **Actions** tab and click **New**.
   - Set **Action** to **Start a program**.
   - In the **Program/script** field, enter:
   
     ```bash
     powershell.exe
     ```

   - In the **Add arguments** field, enter:
   
     ```bash
     -ExecutionPolicy Bypass -File "C:\path_to_script\windows_auto_hotspot.ps1"
     ```

     Replace `"C:\path_to_script\windows_auto_hotspot.ps1"` with the actual path where you saved the script.
   
   ![New Action](./New%20Action.png)

### 6. Configure Conditions and Settings

1. **Conditions**:
   - Uncheck everything in the **Conditions** tab (nothing should be enabled).
   
   ![Conditions Settings](./Conditions.png)

2. **Settings**:
   - In the **Settings** tab, check the following options:
     - **Allow task to be run on demand**.
     - **Run task as soon as possible after a scheduled start is missed**.
     - **Do not start a new instance**.
   
   ![Settings](./Settings.png)

### 7. Done! 🎉

Your script is now set up to run at startup and will check every 5 minutes to enable or disable the hotspot based on the Ethernet connection status.

---

## License 📄

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
