# BLE-Wiretap

Inspired by https://github.com/optiv/blemon/. Compatible with android's new BLE gat callback and shi.

## Usage

All outgoing packets are intercepted by hooking `android.bluetooth.BluetoothGatt`

All incoming packets are intercepted by hooking whatever class that immplements onCharacteristicChanged and onCharacteristicRead.
So, this part requires looking at decompilation to find classes that implementation GattCallback
