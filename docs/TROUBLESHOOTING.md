# SecureChain Troubleshooting Guide

## 1. Common Operational Issues

### 1.1 "Windows administrator privileges are required"
- **Cause**: Attempting to run native Windows route table manipulation or netsh firewall commands without Administrator elevation.
- **Solution**: Run terminal/PowerShell as Administrator, or execute within the default Virtual Simulation Mesh where elevated privileges are not required.

### 1.2 "Cannot transition from [STATE_A] to [STATE_B]"
- **Cause**: An invalid lifecycle transition was attempted violating state machine invariants.
- **Solution**: Check current state using `securechain status`. If in `TRAFFIC_BLOCKED` or `RECOVERY_FAILED`, execute `securechain restart` or `securechain stop`.

### 1.3 "Kill Switch remains locked: Traffic is blocked"
- **Cause**: A tunnel in the active chain dropped, or verification failed.
- **Solution**: Run `securechain health` to inspect which hop failed. Run `securechain restart` to rebuild the pipeline, or check connectivity to remote VPN endpoints.

### 1.4 "DNS Leak Detected"
- **Cause**: Operating system DNS resolver did not switch to the tunnel gateway, or local software overwrote DNS settings.
- **Solution**: Run `securechain test dns` and ensure the interface metric of physical adapters is higher than the tunnel interface metric.
