package de.darkatra.injector

import com.formdev.flatlaf.FlatLightLaf
import java.awt.BorderLayout
import java.awt.Dimension
import java.awt.Rectangle
import java.io.File
import java.nio.file.FileSystems
import java.nio.file.Path
import java.util.stream.Collectors
import java.util.stream.Stream
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JComboBox
import javax.swing.JFileChooser
import javax.swing.JFrame
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JTextField
import javax.swing.border.EmptyBorder
import kotlin.io.path.notExists

class Application {

    init {

        FlatLightLaf.setup()

        JFrame().apply {
            title = "Injector"
            bounds = Rectangle(400, 200)
            defaultCloseOperation = JFrame.EXIT_ON_CLOSE
            setLocationRelativeTo(null)

            val processes = streamProcesses()
                .map { Process(it.info().command().get().substringAfterLast("\\"), it.pid()) }
                .sorted(Comparator.comparing { it.name })
                .collect(Collectors.toList())
                .toTypedArray()

            val processSelect = JComboBox(processes)

            val dllBox = JPanel().apply {
                layout = BorderLayout()
            }

            val dllSelect = JTextField("Absolute Dll Path")
            val dllFileSelectButton = JButton("Select Dll").apply {
                addActionListener {
                    JFileChooser().apply {
                        preferredSize = Dimension(800, 600)
                        fileSelectionMode = JFileChooser.FILES_ONLY
                        currentDirectory = File(System.getProperty("user.home") + FileSystems.getDefault().separator + "Desktop")
                        showOpenDialog(null)
                    }.selectedFile?.let { file ->
                        dllSelect.text = file.absolutePath
                    }
                }
            }

            dllBox.add(dllSelect, BorderLayout.CENTER)
            dllBox.add(dllFileSelectButton, BorderLayout.EAST)

            val container = JPanel().apply {
                setBorder(EmptyBorder(20, 20, 20, 20))
                layout = BorderLayout(10, 10)

                add(JPanel().apply {
                    layout = BoxLayout(this, BoxLayout.Y_AXIS)

                    add(processSelect)
                    add(Box.createRigidArea(Dimension(0, 10)))
                    add(dllBox)
                })
                add(
                    JButton("Inject").apply {
                        addActionListener {

                            val processId = processes[processSelect.selectedIndex].pid
                            val dllPath = Path.of(dllSelect.text)

                            if (dllPath.notExists()) {
                                JOptionPane.showMessageDialog(null, "Dll does not exist")
                                return@addActionListener
                            }

                            Injector.injectDll(processId, dllPath)
                        }
                    },
                    BorderLayout.SOUTH
                )
            }
            add(container)

            isVisible = true
        }
    }

    private fun streamProcesses(): Stream<ProcessHandle> {
        return ProcessHandle.allProcesses()
            .filter { process -> process.info().command().isPresent }
    }
}

fun main() {
    Application()
}
