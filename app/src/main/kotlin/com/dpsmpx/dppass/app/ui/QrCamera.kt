package com.dpsmpx.dppass.app.ui

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.ImageFormat
import android.hardware.camera2.CameraAccessException
import android.hardware.camera2.CameraCaptureSession
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraDevice
import android.hardware.camera2.CameraManager
import android.hardware.camera2.CaptureRequest
import android.hardware.camera2.params.OutputConfiguration
import android.hardware.camera2.params.SessionConfiguration
import android.media.ImageReader
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.Looper
import android.view.SurfaceHolder
import java.util.concurrent.Executor

/**
 * Камера для QR (D-71): Camera2 без AndroidX (D-34). Превью — в
 * поверхность экрана, кадры YUV — в [QrFrame] на своём потоке; найденный
 * текст — [onText] один раз, на главном потоке. Кадры нигде не хранятся и
 * из процесса не уходят.
 *
 * Открывается [open], закрывается [close] — экран зовёт их, когда виден и
 * когда скрыт: в фоне DPpass камеру не держит. Каждое открытие — свой
 * [Run] со своим потоком: к камере, сеансу и читателю кадров обращается
 * только он, а камера, открывшаяся уже после [close], закрывается сразу.
 */
internal class QrCamera(
    private val context: Context,
    private val choice: Choice,
    private val onText: (String) -> Unit,
    private val onFailure: () -> Unit,
) {
    /** Какую камеру открыть и с какими размерами ([QrCameraSizes.choose]). */
    data class Choice(val cameraId: String, val sensorDegrees: Int, val frame: FrameSize, val preview: FrameSize)

    private val main = Handler(Looper.getMainLooper())
    private val manager = context.getSystemService(CameraManager::class.java)
    private var current: Run? = null

    fun open(holder: SurfaceHolder) {
        if (current != null) return
        // Разрешение могли отозвать, пока экран был скрыт.
        if (context.checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            main.post(onFailure)
            return
        }
        holder.setFixedSize(choice.preview.width, choice.preview.height)
        val run = Run(holder)
        current = run
        try {
            manager.openCamera(choice.cameraId, run.callback, run.handler)
        } catch (e: CameraAccessException) {
            run.notOpened()
        } catch (e: SecurityException) {
            run.notOpened()
        } catch (e: IllegalArgumentException) {
            run.notOpened()
        }
    }

    fun close() {
        current?.stop()
        current = null
    }

    /** Одно открытие камеры: от [open] до [close] или отказа. */
    private inner class Run(private val holder: SurfaceHolder) {
        private val thread = HandlerThread("dppass-qr").also { it.start() }
        val handler = Handler(thread.looper)

        // Ставит главный поток (close) и поток камеры (найден код, отказ); после — ничего.
        @Volatile private var done = false

        // Поля ниже — только на потоке камеры.
        private var opening = true
        private var device: CameraDevice? = null
        private var session: CameraCaptureSession? = null
        private val reader = ImageReader.newInstance(choice.frame.width, choice.frame.height, ImageFormat.YUV_420_888, 2).also {
            it.setOnImageAvailableListener({ r -> scan(r) }, handler)
        }
        private var luma = ByteArray(0)

        val callback = object : CameraDevice.StateCallback() {
            override fun onOpened(camera: CameraDevice) {
                opening = false
                device = camera
                if (done) release() else startSession(camera)
            }

            override fun onDisconnected(camera: CameraDevice) {
                opening = false
                camera.close()
                if (done) release() else failed()
            }

            override fun onError(camera: CameraDevice, error: Int) {
                opening = false
                camera.close()
                if (done) release() else failed()
            }
        }

        /** С главного потока: закрыть всё на потоке камеры, после кадра, который сейчас разбирается. */
        fun stop() {
            done = true
            handler.post { if (!opening) release() }
        }

        /** [CameraManager.openCamera] отказал сразу: обратного вызова не будет — закрыть самим. */
        fun notOpened() {
            if (!done) main.post(onFailure)
            done = true
            handler.post {
                opening = false
                release()
            }
        }

        /** Отказ — на экран, один раз; закрытие — тоже по [stop] от экрана. */
        fun failed() {
            if (done) return
            done = true
            main.post(onFailure)
            handler.post { if (!opening) release() }
        }

        /** На потоке камеры: камера, сеанс, читатель кадров — и сам поток. */
        private fun release() {
            try {
                session?.close()
            } catch (e: IllegalStateException) {
                // Камеру уже закрыла система — закрывать нечего.
            }
            session = null
            device?.close()
            device = null
            reader.close()
            thread.quitSafely()
        }

        private fun startSession(camera: CameraDevice) {
            val outputs = listOf(holder.surface, reader.surface)
            val state = object : CameraCaptureSession.StateCallback() {
                override fun onConfigured(s: CameraCaptureSession) {
                    session = s
                    if (done) return release()
                    try {
                        val request = camera.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW).apply {
                            outputs.forEach(::addTarget)
                            set(CaptureRequest.CONTROL_AF_MODE, focusMode())
                        }
                        s.setRepeatingRequest(request.build(), null, handler)
                    } catch (e: CameraAccessException) {
                        failed()
                    } catch (e: IllegalStateException) {
                        failed()
                    }
                }

                override fun onConfigureFailed(s: CameraCaptureSession) = failed()
            }
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    val executor = Executor { handler.post(it) }
                    camera.createCaptureSession(SessionConfiguration(SessionConfiguration.SESSION_REGULAR, outputs.map(::OutputConfiguration), executor, state))
                } else {
                    // До Android 9 другого способа нет: SessionConfiguration — с API 28.
                    @Suppress("DEPRECATION")
                    camera.createCaptureSession(outputs, state, handler)
                }
            } catch (e: CameraAccessException) {
                failed()
            } catch (e: IllegalStateException) {
                failed()
            } catch (e: IllegalArgumentException) {
                // Поверхность превью уже уничтожена: экран ушёл.
                failed()
            }
        }

        /** Непрерывный автофокус, если камера его умеет: код поднесли ближе — резкость сама. */
        private fun focusMode(): Int {
            val modes = manager.getCameraCharacteristics(choice.cameraId).get(CameraCharacteristics.CONTROL_AF_AVAILABLE_MODES)?.toSet().orEmpty()
            return listOf(CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE, CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_VIDEO)
                .firstOrNull { it in modes } ?: CaptureRequest.CONTROL_AF_MODE_OFF
        }

        /** Кадр — на потоке камеры. Пока он разбирается, новые ждут в [ImageReader] и вытесняют друг друга. */
        private fun scan(r: ImageReader) {
            val image = try {
                r.acquireLatestImage()
            } catch (e: IllegalStateException) {
                null
            } ?: return
            val text = try {
                if (done) return
                // Плоскость Y у YUV_420_888 — байт на пиксель (pixelStride = 1), строка — rowStride.
                val plane = image.planes[0]
                val buffer = plane.buffer
                val n = buffer.remaining()
                // Кадр короче, чем обещают размеры, — не разбирать: данные камеры — чужие.
                if (plane.rowStride < image.width || n < plane.rowStride.toLong() * (image.height - 1) + image.width) return
                if (luma.size < n) luma = ByteArray(n)
                buffer.get(luma, 0, n)
                QrFrame.decode(luma, image.width, image.height, plane.rowStride)
            } finally {
                image.close()
            }
            if (text == null || done) return
            done = true
            main.post { onText(text) }
        }
    }

    companion object {
        /** Задняя камера, если есть, иначе первая; null — камер нет или ни одна не отдаёт YUV. */
        fun choose(context: Context): Choice? {
            val manager = context.getSystemService(CameraManager::class.java)
            return try {
                val ids = manager.cameraIdList.sortedBy { id ->
                    if (manager.getCameraCharacteristics(id).get(CameraCharacteristics.LENS_FACING) == CameraCharacteristics.LENS_FACING_BACK) 0 else 1
                }
                ids.firstNotNullOfOrNull { id ->
                    val c = manager.getCameraCharacteristics(id)
                    val map = c.get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP) ?: return@firstNotNullOfOrNull null
                    val frames = map.getOutputSizes(ImageFormat.YUV_420_888)?.map { FrameSize(it.width, it.height) }.orEmpty()
                    val previews = map.getOutputSizes(SurfaceHolder::class.java)?.map { FrameSize(it.width, it.height) }.orEmpty()
                    QrCameraSizes.choose(frames, previews)?.let { (frame, preview) ->
                        Choice(id, c.get(CameraCharacteristics.SENSOR_ORIENTATION) ?: 0, frame, preview)
                    }
                }
            } catch (e: CameraAccessException) {
                null
            } catch (e: IllegalArgumentException) {
                null
            }
        }
    }
}
