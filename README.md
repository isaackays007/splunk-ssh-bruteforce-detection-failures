# Splunk SSH Brute-Force Detection (Failed Logins)

This project detects SSH brute-force activity in Splunk based on repeated failed SSH login attempts against a Linux server, using `linux_secure` authentication logs. The focus here is on noisy failures only (no successful login required).

## 1. Objective

The goal of this lab is to detect SSH brute-force attempts against a Linux host by analyzing repeated failed SSH login attempts in `linux_secure` sshd logs. The detection identifies source IPs and users that generate multiple failed SSH password attempts within a short time window, which is a common brute-force pattern.

## 2. Lab environment

- Splunk Enterprise running in a home lab.  
- Linux server forwarding `/var/log/auth.log` / `linux_secure` SSH auth logs to Splunk.  
- Kali Linux attacker VM generating SSH brute-force traffic with tools like `hydra`.  
- Index: `main`, sourcetype: `linux_secure`.

## 3. Data and exploration

I first validated that SSH authentication logs were ingested into Splunk as `linux_secure` events. By searching for `Failed password` messages, I confirmed that failed SSH login attempts from the attacker IP against my test user were visible in the data.

```spl
index=main sourcetype=linux_secure "Failed password"
```
![SSH failed password events](screenshots/events_failed_password.png)

## 4. Detection logic (SPL)

To detect brute-force behavior based on failed logins only, I used the following SPL:

```spl
index=main sourcetype=linux_secure "Failed password"
| rex "Failed password for (invalid user )?(?<user>\S+) from (?<src>\d+\.\d+\.\d+\.\d+)"
| stats count AS failed_count min(_time) AS first_attempt max(_time) AS last_attempt BY src user
| where failed_count >= 5
```

This search filters for failed SSH authentication messages, extracts the username and source IP, then aggregates failed attempts per `src` and `user`. It flags any IP–user pair with at least five failed SSH password attempts in the selected time window as potential brute-force action.

![Brute-force aggregation statistics](screenshots/stats_bruteforce_table.png)

## 5. Alert configuration

I converted this search into a scheduled alert in Splunk:

- Schedule: Runs every 1 minute.  
- Time range: Last 5 minutes.  
- Trigger condition: Number of results is greater than 0.  
- Severity: High.  
- Action: Add to Triggered Alerts (UI).

This configuration raises a High-severity alert whenever an IP–user pair generates five or more failed SSH login attempts within five minutes, so a SOC analyst can investigate the source and apply blocking if needed.

![Alert configuration](screenshots/alert_configuration.png)
![Triggered alert results](screenshots/alert_view_results.png)

## 6. Results and observations

When I launched the SSH brute-force attack from the Kali VM, the search and alert correctly identified the attacker IP and test user as having multiple failed SSH password attempts within the 5-minute window. This demonstrates how Splunk can detect SSH brute-force attempts using Linux authentication logs, even when the attacker never successfully logs in.

## 7. Skills demonstrated

- Building SPL searches to detect repeated failed authentication attempts.  
- Using `rex` for field extraction and `stats` for aggregation by source IP and user.   
- Creating a scheduled alert in Splunk based on result count over a moving time window.  
- Simulating SSH brute-force attacks in a lab and documenting the detection for a security portfolio.
```
