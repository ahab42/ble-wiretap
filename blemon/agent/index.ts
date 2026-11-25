import Java from "frida-java-bridge";

function bytes2hex(array: ArrayLike<number>): string {
  let result = "";
  for (let i = 0; i < array.length; ++i)
    result += ("0" + (array[i] & 0xff).toString(16)).slice(-2);
  return result;
}

function emit(dir: string, uuid: any, data: any): void {
  send({ dir, uuid: uuid.toString(), data: data ? bytes2hex(data) : "" });
}

const hooked: { [name: string]: boolean } = {};

function hookCallbackClass(name: string) {
  if (hooked[name]) return;
  hooked[name] = true;
  send({ dir: "info", uuid: "", data: "hooking " + name });
  const Cls = Java.use(name);
  const methods: [string, string][] = [
    ["onCharacteristicRead", "read"],
    ["onCharacteristicChanged", "notify"],
  ];
  methods.forEach(([method, dir]) => {
    if (!Cls[method]) return;
    Cls[method].overloads.forEach((ov: any) => {
      ov.implementation = function (...args: any[]) {
        const c = args[1];
        const t = ov.argumentTypes[2];
        const hasValue = t && t.className === "[B";
        emit(dir, c.getUuid(), hasValue ? args[2] : c.getValue());
        return ov.apply(this, args);
      };
    });
  });
}

const incoming_classes = ["a7.g"]

Java.perform(() => {
  const Gatt = Java.use("android.bluetooth.BluetoothGatt");

  Gatt.writeCharacteristic.overloads.forEach((ov: any) => {
    ov.implementation = function (...args: any[]) {
      const c = args[0];
      emit("write", c.getUuid(), args.length === 3 ? args[1] : c.getValue());
      return ov.apply(this, args);
    };
  });

  // target class confirmed from decompile
  incoming_classes.forEach(hookCallbackClass);
});
