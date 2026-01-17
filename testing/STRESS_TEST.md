# pyIRCX Stress Test & Load Testing

## ⚠️ RESPONSIBLE USE ONLY

**This stress test is for testing YOUR OWN pyIRCX servers.**

### Acceptable Use:
- ✅ Testing your own pyIRCX installation
- ✅ Validating server performance
- ✅ Load testing before production deployment
- ✅ Benchmarking improvements
- ✅ Debugging scalability issues

### PROHIBITED Use:
- ❌ Testing servers you don't own/operate
- ❌ Attacking third-party IRC servers
- ❌ Any form of denial-of-service attack
- ❌ Circumventing server connection limits

**Violating these terms may be illegal in your jurisdiction.**

---

## What It Tests

The stress test simulates realistic IRC usage with:

- **Regular Users** (90%): Join/part channels, chat, change nicks
- **Staff Users** (5%): Mode changes, topics, stats commands
- **Service Users** (5%): Register nicks, send offline messages

### Scenarios Simulated

1. **Concurrent Connections** - Multiple users connecting simultaneously
2. **Channel Activity** - Users joining/leaving channels dynamically
3. **Message Traffic** - Realistic chat patterns and rates
4. **Staff Operations** - Mode changes, kicks, stats queries
5. **Cross-Server Load** - Distributed across trunk + branches
6. **Service Load** - Registration, offline messages, help queries

---

## Usage

### Quick Test (50 users, 1 minute)
```bash
python3 testing/stress_test.py --quick
```

### Standard Test (100 users, 5 minutes)
```bash
python3 testing/stress_test.py
```

### Custom Test
```bash
python3 testing/stress_test.py --users 200 --staff 10 --channels 30 --duration 600
```

### Heavy Load Test (500 users, 10 minutes)
```bash
python3 testing/stress_test.py --heavy
```

---

## Options

```
--users N       Number of concurrent users (default: 100)
--staff N       Number of staff users (default: 5)
--channels N    Number of channels to use (default: 20)
--duration N    Test duration in seconds (default: 300)
--quick         Preset: 50 users, 60s
--heavy         Preset: 500 users, 600s
```

---

## Requirements

### Running Servers

Stress test expects these servers running:

- **Trunk**: 127.0.0.1:6667 (services hub)
- **Branch 1**: 127.0.0.1:6668
- **Branch 2**: 127.0.0.1:6669

### Server Configuration

For best results, configure your test servers:

```json
{
  "limits": {
    "max_users": 10000,
    "max_channels": 2500,
    "client_timeout": 600
  },
  "security": {
    "flood_protection": false
  }
}
```

**Disable flood protection** during stress testing to avoid artificial throttling.

---

## What to Expect

### Console Output

```
================================================================================
                        pyIRCX v2.0.0 Stress Test
================================================================================

Generated 20 channels: #test1, #test2, #test3, #test4, #test5...

Creating 100 clients...
  Connected: 10/100
  Connected: 20/100
  ...
  Connected: 100/100
✓ 100 clients connected, 0 failed

Stress test running...
Duration: 300s
Servers: 3
Channels: 20

[30s] Active clients: 100/100 | Remaining: 270s
[60s] Active clients: 100/100 | Remaining: 240s
...

Cleaning up...
✓ Cleanup complete

================================================================================
                        Stress Test Complete
================================================================================
Duration:          300s
Clients created:   100
Clients connected: 100
Connection failures: 0
Success rate:      100.0%

✓ All clients connected successfully!
```

### Server Logs

You should see in your server logs:

```
[INFO] User1 connected from 127.0.0.1
[INFO] User2 connected from 127.0.0.1
...
[INFO] #test1: User5 joined
[INFO] #test2: User12 joined
...
[INFO] Network activity: 100 users, 45 channels
```

---

## Interpreting Results

### Success Metrics

- **100% connection success** - All clients connect
- **No server crashes** - Server remains stable
- **Responsive** - Commands processed in < 1s
- **Low memory growth** - Memory usage stable
- **Clean logs** - No error messages

### Warning Signs

- **Connection failures** - Server overloaded or config issue
- **High latency** - Commands taking > 5s to process
- **Memory leaks** - Memory usage growing continuously
- **Errors in logs** - Database errors, exceptions
- **Disconnections** - Clients dropping unexpectedly

---

## Benchmarking

### Baseline Performance (Example)

**Test System:**
- Intel i7-8700K (6 cores)
- 16GB RAM
- Ubuntu 22.04 LTS
- Python 3.10

**Results:**
- 500 concurrent users: ✓ Stable
- 50 channels active: ✓ No lag
- Message rate: ~200/sec peak: ✓ Handled
- CPU usage: ~40% average
- Memory: ~150MB steady state

### Your Results

Document your stress test results:

```bash
# Run stress test and save output
python3 testing/stress_test.py --heavy 2>&1 | tee stress_test_results.txt

# Check server resource usage during test
# Terminal 1: Run stress test
# Terminal 2: Monitor server
top -p $(pgrep -f pyircx.py)
```

---

## Troubleshooting

### "Connection refused"

**Problem:** Clients can't connect to servers

**Solutions:**
- Ensure servers are running: `ps aux | grep pyircx`
- Check listening ports: `netstat -tlnp | grep python`
- Verify firewall: `sudo ufw status`

### "Too many open files"

**Problem:** OS file descriptor limit reached

**Solution:**
```bash
# Increase limit temporarily
ulimit -n 4096

# Or permanently edit /etc/security/limits.conf
* soft nofile 4096
* hard nofile 8192
```

### Server becomes unresponsive

**Problem:** Server stops responding during test

**Causes:**
- Database lock contention
- CPU exhaustion
- Memory exhaustion
- Network buffer overflow

**Solutions:**
- Enable database WAL mode: `PRAGMA journal_mode=WAL`
- Increase `database.pool_size` in config
- Reduce stress test intensity
- Profile server performance

### Test never completes

**Problem:** Stress test hangs

**Solution:**
```bash
# Interrupt with Ctrl+C
# Cleanup may take a few seconds
```

---

## Best Practices

### Before Production

1. **Run quick test** - Verify basic functionality
2. **Run standard test** - Ensure stability under load
3. **Run heavy test** - Find breaking point
4. **Monitor resources** - Check CPU, memory, disk I/O
5. **Review logs** - Look for errors or warnings
6. **Tune configuration** - Optimize based on results

### During Testing

- Monitor server logs in real-time
- Watch system resource usage
- Test incrementally (50 → 100 → 200 → 500 users)
- Allow cooldown between tests
- Save results for comparison

### After Testing

- Review all metrics
- Document any issues found
- File bug reports if crashes occur
- Share performance results
- Optimize configuration

---

## Safety Features

The stress test includes built-in safety:

1. **Local only** - Only connects to 127.0.0.1 by default
2. **Configurable limits** - Control load intensity
3. **Graceful shutdown** - Ctrl+C cleanly disconnects
4. **Connection limits** - Respects OS/server limits
5. **Realistic patterns** - Not designed as attack tool

---

## License

Stress test is part of pyIRCX and licensed under AGPL v3.

**Use responsibly. Test only your own servers.**

Copyright (C) 2026 pyIRCX Project
