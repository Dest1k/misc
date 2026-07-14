# Driver resolver design sketch

A read-only resolver should map a normalized `.sys` path to service registry
entry, file signature/version, published INF, Driver Store package, PnP device
instance and hardware IDs. It must handle shared class/filter drivers and return
multiple candidates rather than guessing.

No package change should be automated until snapshot, package backup, reboot
health check and rollback have been implemented and tested on disposable VMs.
