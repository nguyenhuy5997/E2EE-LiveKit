package com.evt2.board.link

import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager

/**
 * Matches EVT2's encryption device by USB VID:PID (stable across replugs /
 * port renumbering, unlike a fixed port/device path).
 */
data class UsbDeviceMatch(val vid: Int, val pid: Int)

object UsbPortFinder {
    /** EVT2's USB_DEVICE/App/usbd_desc.c: USBD_VID=0x0483, USBD_PID_FS=0x5740
     *  (the ST demo VID/PID -- confirmed by reading that file directly). */
    val DEFAULT_MATCH = UsbDeviceMatch(vid = 0x0483, pid = 0x5740)

    fun findDevice(usbManager: UsbManager, match: UsbDeviceMatch): UsbDevice? {
        return usbManager.deviceList.values.firstOrNull {
            it.vendorId == match.vid && it.productId == match.pid
        }
    }
}
