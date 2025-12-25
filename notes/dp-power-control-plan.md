# DP power control bringup

## Goal
Add a software-controlled switch to cut VBUS / DP power path so external monitor doesn't drain battery.

## Leads to investigate
- Type-C / USB-PD: tcpm, qcom typec, pmic/qpnp-smb5, extcon state nodes
- DP display: dp_display node, possible lt9611/lontium bridge, redriver, regulators

## Evidence already observed
- extcon DP states exist under /sys/class/extcon/*
- dp_display exists under /sys/devices/platform/soc/.../dp_display
- qpnp-smb5 / power_supply/usb nodes exist

## Next steps
1) Identify regulator(s) powering DP path + VBUS boost
2) Find DT nodes referencing those regulators (vendor_fdt_0.dts / kernel dts)
3) Add a controllable sysfs/debugfs or input hook (temporary)
4) Wire to regulator_disable()/enable() and/or Type-C role/PD disable
