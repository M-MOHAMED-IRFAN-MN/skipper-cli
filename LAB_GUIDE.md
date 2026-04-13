# 🛡️ Free SOC Analyst Lab with skipper

This guide turns skipper into a **completely free, unlimited-attempt training lab** for aspiring SOC analysts.

## 🎯 What You'll Learn
- Real-time log monitoring (like Splunk Live Tail)
- Detecting brute force, SQLi, and directory traversal
- Generating your own attack traffic for practice

## 🧪 Step 1: Setup Your Lab Environment
1. Install skipper: `pip install -e .`
2. (Optional) Download **Metasploitable 2** VM for real attack simulation.

## 💻 Step 2: Start the Live Monitor
```bash
skipper monitor /var/log/apache2/access.log