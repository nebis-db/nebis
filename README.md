# **Nebis Quick Start**
This README is a quick introduction to Nebis, a cutting-edge in-memory database designed to combine the speed of RAM with the reliability of disk persistence. For more detailed documentation, visit our website.

### **What is Nebis?**
Nebis is a RAM-based database with optional disk persistence. It offers an HTTP-based API for universal accessibility, making it compatible with any programming language. Here’s what makes Nebis special:

- **In-memory data processing:** For ultra-fast performance.
- **Disk persistence:** Reliable storage using JSON.
- **Dynamic structures:** Automates "table and column" management.
- **Security built-in:** AES-256 encryption and JWT authentication.
- **Offline synchronization:** Perfect for mobile and distributed systems.

---

### **Getting Started**
#### Prerequisites
Nebis requires Python 3.8 or later to run. Make sure Python is installed on your system. Optionally, install Docker if you prefer containerized deployment.

#### Installation
```bash
pip install nebis-cli
```

#### Running Nebis
```bash
nebis
```

#### Using Nebis with Nebis Cloud
If you're planning to use **Nedis Cloud** for managing your databases, **nebis-cli** will be required. It allows you to:

- Create and manage your account.
- Log in to your Nebis Cloud account.
- Create and delete databases.
- Obtain your unique Nebis URL for database connections.

#### Using Nebis Locally
If you're storing your databases locally, you don't need **nebis-cli**. Simply download and import **nebis** into your development project to save everything locally, and start using the database without the need for an online connection.

Enjoy!
