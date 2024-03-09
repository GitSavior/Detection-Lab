# Detection Lab project

## Objective

The Detection Lab project provides a controlled environment for simulating and detecting cyber-attacks. It focuses on analyzing logs in a SIEM system and generating test telemetry to simulate real-world scenarios. This hands-on training seeks to improve understanding of network security, attack patterns, and defensive tactics.

### Skills Learned

- Build a sandbox enviornment
- Understanding of SIEM concepts and practical application.
- Proficiency in analyzing and interpreting network logs.
- Enhanced knowledge of network protocols and security vulnerabilities.
- Development of critical thinking and problem-solving skills in cybersecurity.

### Tools Used

- Vitural machine (VirtualBox) for sandbox evironment. 
- Splunk a Security Information and Event Management (SIEM) system for log ingestion and analysis.
- Telemetry generation tools to create realistic network traffic and attack scenarios.

## Steps

##### Step 1: To begin, this project constructed two virtual machine operating systems (VM). One victim machine (Windows 10) and one attack machine (Kali Linux). To imitate a confined environment, two VMs will be created and connected via an internal network.

![1](https://github.com/GitSavior/Detection-Lab/assets/162067776/41654a02-dadd-4778-818b-357b3c6bf5ec)

##### Step 2: After installing the OSs VMs, a backup will be produced for each machine to establish a baseline. A backup was created in case damage occurred during testing and rendered the system inoperable, for example.

Victim Baseline (Windows 10)
![2](https://github.com/GitSavior/Detection-Lab/assets/162067776/43da70e8-af26-4556-9846-953ae4ec3c21)


Attack Machine Baseline (Kali Linux)
![3](https://github.com/GitSavior/Detection-Lab/assets/162067776/e561f0c2-5247-4296-8cfe-afcfa5043602)

##### Step 3: After backing up the VM OSs, the next step is to configure an internal network that allows the systems to communicate. Communication will only be permitted between the victim and attack machines. The goal is to prevent these two machines from communicating and perhaps infecting other machines on the network with malware.

Internal Network Setup (Windows 10)

![4](https://github.com/GitSavior/Detection-Lab/assets/162067776/05495a0f-d110-469f-b0e3-780d2278ae0e)

Internal Network Setup (Kali Linux)

![5](https://github.com/GitSavior/Detection-Lab/assets/162067776/459d77b1-ba7d-4bed-bc00-cbd54ba97fd5)

##### Step 4: When the machines are powered on one will observe that there is no network connectivity between the two machines. To allow the machines to communicate, a local IP address has to be created.

Creating a local IP address (Window 10)

![7](https://github.com/GitSavior/Detection-Lab/assets/162067776/f52a0881-95a6-40ef-9dd9-eb84d1307900)

Creating a local IP address (Kali Linux)

![6](https://github.com/GitSavior/Detection-Lab/assets/162067776/a95af9e7-c227-4e75-9f4a-9cfc4c593ceb)

Pinging the victim machine from the attack machine shows they are now communicating

![8](https://github.com/GitSavior/Detection-Lab/assets/162067776/9118d0b5-6653-467f-8741-293f172018de)

##### Step 5: Creating a reverse shell to simulate a successful attack on the victim machine. Splunk a SIEM is installed on the victim system to practice monitoring and detecting logs.

![9](https://github.com/GitSavior/Detection-Lab/assets/162067776/56021e11-54e6-4a5c-a492-347eddfb23f8)

![10](https://github.com/GitSavior/Detection-Lab/assets/162067776/1ff093fc-0b23-427a-a484-5ea7b8228c74)

##### Step 6: Using the metasploit framework to select a listener. The selected tool "multi/handler" is configured to the type of revese_shell produced with msfvenom.

![image](https://github.com/GitSavior/Detection-Lab/assets/162067776/f75a495e-240c-4ba1-b9ef-4e87473d8087)

##### Step 7: Creating a server from the attack machine that the  victim can use to download the malware created by Msfvenom

![image](https://github.com/GitSavior/Detection-Lab/assets/162067776/bd2398a4-3d78-4fba-bc29-0e54fba61397)

##### Step 8: Disabling the Windows Defender to allow the malware to infect the victim machine, so that the activity can be monitored from the SIEM.

![13](https://github.com/GitSavior/Detection-Lab/assets/162067776/eb321c59-a0e8-4c21-8ca6-adb05f2125dc)

##### Step 9: Download the file from the attacker machine using a browser on the victim machine.

![14](https://github.com/GitSavior/Detection-Lab/assets/162067776/b1819d8d-923e-4345-a077-25ee5c460dd4)

##### Step 10: Run the malware and then see if there is an established connections using “netstat- anob” in cmd

Downloaded Malware

![15](https://github.com/GitSavior/Detection-Lab/assets/162067776/f9f0e0d3-5d65-435f-bbd5-17726719c682)

CMD "netstat -anob"

![16](https://github.com/GitSavior/Detection-Lab/assets/162067776/4e1df65a-4d24-4cea-acda-d0fe48973233)

Can see the malware in Task Manager under details. The PID is the same from cmd output.

![17](https://github.com/GitSavior/Detection-Lab/assets/162067776/7082991f-9047-4b34-9c71-1180f62bb37d)

##### Step 11: Switching to the attack machine in the terminal reveals that the attack was successful.

![18](https://github.com/GitSavior/Detection-Lab/assets/162067776/492afbbc-540f-4a45-a3d1-db7689747cb8)

The help command displays all of the meterpreter tools that are available for use.
For example, here are some commands that we can use:

![19](https://github.com/GitSavior/Detection-Lab/assets/162067776/190a9580-9d14-4a52-80d5-d9dd8d81a79f)

##### Step 12: Type "shell" and press enter to utilize the attacker shell to run ipconfig to check our connection to the victim machine.

![20](https://github.com/GitSavior/Detection-Lab/assets/162067776/9d5dbe74-3a73-43ac-9ab4-a50990b43f5d)

##### Step 13: Configure sysmon in our splunk input.conf file 

![21](https://github.com/GitSavior/Detection-Lab/assets/162067776/ca0599f2-ec09-41aa-85af-caaf00117603)

This syntax is used to tell Splunk to look into the Microsoft-Windows-Sysmom/Operational and feed all the events into the index endpoint.

![22](https://github.com/GitSavior/Detection-Lab/assets/162067776/2811cdce-098a-48ed-a4fa-29e7f2afea73)

##### Step 14: Create an index called endpoint in Splunk to point back to the input.conf index endpoint from step 13.

![23](https://github.com/GitSavior/Detection-Lab/assets/162067776/25e5e6cd-0967-47ad-b177-09fedaf829bd)

##### Step 15: Using the Splunk Search & reporting app, perform a new search "index=endpoint" to see the information populate in our environment. 

![24](https://github.com/GitSavior/Detection-Lab/assets/162067776/d88b6095-5666-4d87-bde8-3fce349fa109)

##### Step 16: Doing a new Query “index=enpoint 192.168.20.11” pointed to attack machine

![25](https://github.com/GitSavior/Detection-Lab/assets/162067776/9f004cab-2ac6-4d52-b60c-fe5ed3bb5013)

Can see the destination port from our listener. Consider the following question: is this a port that was to be open?

![26](https://github.com/GitSavior/Detection-Lab/assets/162067776/767485b7-005c-45bb-89f1-b04add1359f0)

##### Step 17: Creating a new query to point to the malware program itself to investigate it  thoroughly.

![34](https://github.com/GitSavior/Detection-Lab/assets/162067776/0ea89055-73b5-41f3-9030-3434718581bc)

Here we are give six event code and will be analyzing event code number “1”

![27](https://github.com/GitSavior/Detection-Lab/assets/162067776/41441760-d523-4b26-bfc6-9ad6e764c057)

We need to expand this event to see the even actions

![28](https://github.com/GitSavior/Detection-Lab/assets/162067776/7bafbd7c-0fbd-4156-a794-5e81863cec02)

Here is the parent process project1.pdf.exe

![29](https://github.com/GitSavior/Detection-Lab/assets/162067776/2312283d-7367-4646-a466-05e559a40956)

The parent process spawned cmd.exe

![30](https://github.com/GitSavior/Detection-Lab/assets/162067776/f50de9eb-740e-4de2-bf6b-7e6465f88b78)

With the process_id 1800, one could utilize this id to query our data and check what this command prompt had done by searching this id using parent process

![31](https://github.com/GitSavior/Detection-Lab/assets/162067776/22b29e58-4e14-4d0a-9128-1ec6f7708ad3)

You can use the process_guid to create Create a query to gain a better understanding of the process structure.

![32](https://github.com/GitSavior/Detection-Lab/assets/162067776/e0504864-397d-4a34-ade0-32e87de8a67f)

See can see the event that project1.pfd.exe spawned cmd.exe below

![33](https://github.com/GitSavior/Detection-Lab/assets/162067776/83e429d7-3705-43cb-a020-543cda6ab001)
