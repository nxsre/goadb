package adb

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zach-klippenstein/goadb/internal/errors"
	"github.com/zach-klippenstein/goadb/wire"
)

// MtimeOfClose should be passed to OpenWrite to set the file modification time to the time the Close
// method is called.
var MtimeOfClose = time.Time{}

// Device communicates with a specific Android device.
// To get an instance, call Device() on an Adb.
type Device struct {
	server     server
	descriptor DeviceDescriptor

	// Used to get device info.
	deviceListFunc func() ([]*DeviceInfo, error)
}

func (c *Device) String() string {
	return c.descriptor.String()
}

// get-product is documented, but not implemented, in the server.
// TODO(z): Make product exported if get-product is ever implemented in adb.
func (c *Device) product() (string, error) {
	attr, err := c.getAttribute("get-product")
	return attr, wrapClientError(err, c, "Product")
}

func (c *Device) Serial() (string, error) {
	attr, err := c.getAttribute("get-serialno")
	return attr, wrapClientError(err, c, "Serial")
}

func (c *Device) DevicePath() (string, error) {
	attr, err := c.getAttribute("get-devpath")
	return attr, wrapClientError(err, c, "DevicePath")
}

func (c *Device) State() (DeviceState, error) {
	attr, err := c.getAttribute("get-state")
	if err != nil {
		if strings.Contains(err.Error(), "unauthorized") {
			return StateUnauthorized, nil
		}
		return StateInvalid, wrapClientError(err, c, "State")
	}
	state, err := parseDeviceState(attr)
	return state, wrapClientError(err, c, "State")
}

func (c *Device) DeviceInfo() (*DeviceInfo, error) {
	// Adb doesn't actually provide a way to get this for an individual device,
	// so we have to just list devices and find ourselves.

	serial, err := c.Serial()
	if err != nil {
		return nil, wrapClientError(err, c, "GetDeviceInfo(GetSerial)")
	}

	devices, err := c.deviceListFunc()
	if err != nil {
		return nil, wrapClientError(err, c, "DeviceInfo(ListDevices)")
	}

	for _, deviceInfo := range devices {
		if deviceInfo.Serial == serial {
			return deviceInfo, nil
		}
	}

	err = errors.Errorf(errors.DeviceNotFound, "device list doesn't contain serial %s", serial)
	return nil, wrapClientError(err, c, "DeviceInfo")
}

/*
RunCommand runs the specified commands on a shell on the device.

From the Android docs:

	Run 'command arg1 arg2 ...' in a shell on the device, and return
	its output and error streams. Note that arguments must be separated
	by spaces. If an argument contains a space, it must be quoted with
	double-quotes. Arguments cannot contain double quotes or things
	will go very wrong.

	Note that this is the non-interactive version of "adb shell"

Source: https://android.googlesource.com/platform/system/core/+/master/adb/SERVICES.TXT

This method quotes the arguments for you, and will return an error if any of them
contain double quotes.
*/
func (c *Device) RunCommand(cmd string, args ...string) (string, error) {
	cmd, err := prepareCommandLine(cmd, args...)
	if err != nil {
		return "", wrapClientError(err, c, "RunCommand")
	}

	conn, err := c.dialDevice()
	if err != nil {
		return "", wrapClientError(err, c, "RunCommand")
	}
	defer conn.Close()

	req := fmt.Sprintf("shell:%s", cmd)

	// Shell responses are special, they don't include a length header.
	// We read until the stream is closed.
	// So, we can't use conn.RoundTripSingleResponse.
	if err = conn.SendMessage([]byte(req)); err != nil {
		return "", wrapClientError(err, c, "RunCommand")
	}
	if _, err = conn.ReadStatus(req); err != nil {
		return "", wrapClientError(err, c, "RunCommand")
	}

	resp, err := conn.ReadUntilEof()
	return string(resp), wrapClientError(err, c, "RunCommand")
}
func (c *Device) RunCommandWithShell(cmd string, args ...string) (*wire.Conn, error) {
	cmd, err := prepareCommandLine(cmd, args...)
	if err != nil {
		return nil, wrapClientError(err, c, "RunCommand")
	}

	conn, err := c.dialDevice()
	if err != nil {
		return nil, wrapClientError(err, c, "RunCommand")
	}

	req := fmt.Sprintf("shell:%s", cmd)

	// Shell responses are special, they don't include a length header.
	// We read until the stream is closed.
	// So, we can't use conn.RoundTripSingleResponse.
	if err = conn.SendMessage([]byte(req)); err != nil {
		return nil, wrapClientError(err, c, "RunCommand")
	}
	if _, err = conn.ReadStatus(req); err != nil {
		return nil, wrapClientError(err, c, "RunCommand")
	}

	return conn, wrapClientError(err, c, "RunCommand")
}

func (c *Device) CreateDeviceConnection() (*wire.Conn, error) {
	return c.dialDevice()
}

func (c *Device) DialLocalAbstractSocket(socketName string) (*wire.Conn, error) {
	conn, err := c.dialDevice()
	if err != nil {
		return nil, wrapClientError(err, c, "DialSocket")
	}
	req := fmt.Sprintf("localabstract:%s", socketName)
	if err = conn.SendMessage([]byte(req)); err != nil {
		return nil, wrapClientError(err, c, "DialSocket")
	}
	if _, err = conn.ReadStatus(req); err != nil {
		return nil, wrapClientError(err, c, "DialSocket")
	}

	return conn, nil
}

func (c *Device) Push(data []byte, remotePath string) error {
	slashPath := filepath.ToSlash(remotePath)
	if strings.HasSuffix(slashPath, "/") {
		return fmt.Errorf("file name not set")
	}

	writer, err := c.OpenWrite(slashPath, os.ModePerm, time.Now())
	if err != nil {
		return wrapClientError(err, c, "Push")
	}
	defer writer.Close()
	_, err = writer.Write(data)
	time.Sleep(1 * time.Second)
	return wrapClientError(err, c, "Push")
}

func (c *Device) PushFile(localPath, remotePath string) error {
	file, err := os.ReadFile(localPath)

	if err != nil {
		return err
	}

	lastByte := remotePath[len(remotePath)-1]
	if lastByte == '/' || lastByte == '\\' {
		remotePath = filepath.Join(remotePath, filepath.Base(localPath))
	}

	return c.Push(file, remotePath)
}

func (c *Device) Pull(remotePath string) ([]byte, error) {
	reader, err := c.OpenRead(filepath.ToSlash(remotePath))
	if err != nil {
		return nil, wrapClientError(err, c, "Pull")
	}
	defer func() {
		_ = reader.Close()
	}()
	return io.ReadAll(reader)
}

func (c *Device) PullFile(remotePath, localPath string) error {
	reader, err := c.OpenRead(filepath.ToSlash(remotePath))
	if err != nil {
		return wrapClientError(err, c, "Pull")
	}
	defer func() {
		_ = reader.Close()
	}()

	localDir := filepath.Dir(localPath)
	if _, err := os.Stat(localDir); os.IsNotExist(err) {
		if err := os.MkdirAll(localDir, os.ModePerm); err != nil {
			return err
		}
	}

	localInfo, err := os.Stat(localPath)
	if err == nil && localInfo.IsDir() {
		localPath = filepath.Join(localPath, filepath.Base(remotePath))
	}

	file, err := os.Create(localPath)
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
	}()

	_, err = io.Copy(file, reader)
	return err

}

func (c *Device) install(apkPath string, args ...string) error {
	args = append(append([]string{"install"}, args...), apkPath)

	res, err := c.RunCommand("pm", args...)

	if err != nil {
		return err
	}
	slog.Info(fmt.Sprintf("[adb_install]install apk:%s", filepath.Base(apkPath)), "res", res)
	return nil
}

func (c *Device) Install(data []byte, apkName string, args ...string) error {
	tmpPath := "/data/local/tmp/"
	apkPath := filepath.ToSlash(filepath.Join(tmpPath, apkName))
	if err := c.Push(data, apkPath); err != nil {
		return err
	}

	return c.install(apkPath, args...)
}

func (c *Device) InstallAPK(filePath string, args ...string) error {
	tmpPath := "/data/local/tmp/"
	if err := c.PushFile(filePath, tmpPath); err != nil {
		return err
	}
	fileName := filepath.Base(filePath)
	apkPath := filepath.ToSlash(filepath.Join(tmpPath, fileName))

	return c.install(apkPath, args...)
}

func (c *Device) Uninstall(packageName string) error {
	res, err := c.RunCommand("pm", "uninstall", packageName)

	if err != nil {
		return err
	}
	slog.Info(fmt.Sprintf("[adb_uninstall]uninstall package:%s", packageName), "res", res)
	return nil
}

func (c *Device) Forward(local, remote string, noRebind bool) error {
	cmd := ""
	serial, err := c.Serial()
	if err != nil {
		return err
	}
	if noRebind {
		cmd = fmt.Sprintf("host-serial:%s:forward:norebind:%s;%s", serial, local, remote)
	} else {
		cmd = fmt.Sprintf("host-serial:%s:forward:%s;%s", serial, local, remote)
	}
	conn, err := c.dialDevice()
	if err != nil {
		return wrapClientError(err, c, "Forward")
	}
	defer conn.Close()

	if err = conn.SendMessage([]byte(cmd)); err != nil {
		return wrapClientError(err, c, "Forward")
	}
	if _, err := conn.ReadStatus(cmd); err != nil {
		return wrapClientError(err, c, "Forward")
	}
	return nil
}

func (c *Device) ForwardKill(local string) error {
	serial, err := c.Serial()
	if err != nil {
		return err
	}
	conn, err := c.dialDevice()
	if err != nil {
		return wrapClientError(err, c, "ForwardKill")
	}
	cmd := fmt.Sprintf("host-serial:%s:killforward:%s", serial, local)
	if err = conn.SendMessage([]byte(cmd)); err != nil {
		return wrapClientError(err, c, "ForwardKill")
	}
	if _, err := conn.ReadStatus(cmd); err != nil {
		return wrapClientError(err, c, "ForwardKill")
	}
	return nil
}

func (c *Device) ForwardKillAll() error {
	list, err := c.ForwardList()
	if err != nil {
		return err
	}
	var res error = nil
	for _, info := range list {
		err := c.ForwardKill(info.Local)
		if err != nil {
			res = err
		}
	}
	return res
}

func (c *Device) ForwardList() ([]ForwardInfo, error) {
	serial, err := c.Serial()
	if err != nil {
		return nil, err
	}
	conn, err := c.dialDevice()
	if err != nil {
		return nil, wrapClientError(err, c, "ForwardList")
	}
	cmd := fmt.Sprintf("host-serial:%s:list-forward", serial)
	resp, err := conn.RoundTripSingleResponse([]byte(cmd))
	if err != nil {
		return nil, wrapClientError(err, c, "ForwardList")
	}
	forwardInfos := parseForwardInfo(resp)
	return forwardInfos, nil
}

/*
Remount, from the official adb command’s docs:

	Ask adbd to remount the device's filesystem in read-write mode,
	instead of read-only. This is usually necessary before performing
	an "adb sync" or "adb push" request.
	This request may not succeed on certain builds which do not allow
	that.

Source: https://android.googlesource.com/platform/system/core/+/master/adb/SERVICES.TXT
*/
func (c *Device) Remount() (string, error) {
	conn, err := c.dialDevice()
	if err != nil {
		return "", wrapClientError(err, c, "Remount")
	}
	defer conn.Close()

	resp, err := conn.RoundTripSingleResponse([]byte("remount"))
	return string(resp), wrapClientError(err, c, "Remount")
}

func (c *Device) ListDirEntries(path string) (*DirEntries, error) {
	conn, err := c.getSyncConn()
	if err != nil {
		return nil, wrapClientError(err, c, "ListDirEntries(%s)", path)
	}

	entries, err := listDirEntries(conn, path)
	return entries, wrapClientError(err, c, "ListDirEntries(%s)", path)
}

func (c *Device) Stat(path string) (*DirEntry, error) {
	conn, err := c.getSyncConn()
	if err != nil {
		return nil, wrapClientError(err, c, "Stat(%s)", path)
	}
	defer conn.Close()

	entry, err := stat(conn, path)
	return entry, wrapClientError(err, c, "Stat(%s)", path)
}

func (c *Device) OpenRead(path string) (io.ReadCloser, error) {
	conn, err := c.getSyncConn()
	if err != nil {
		return nil, wrapClientError(err, c, "OpenRead(%s)", path)
	}

	reader, err := receiveFile(conn, path)
	return reader, wrapClientError(err, c, "OpenRead(%s)", path)
}

// OpenWrite opens the file at path on the device, creating it with the permissions specified
// by perms if necessary, and returns a writer that writes to the file.
// The files modification time will be set to mtime when the WriterCloser is closed. The zero value
// is TimeOfClose, which will use the time the Close method is called as the modification time.
func (c *Device) OpenWrite(path string, perms os.FileMode, mtime time.Time) (io.WriteCloser, error) {
	conn, err := c.getSyncConn()
	if err != nil {
		return nil, wrapClientError(err, c, "OpenWrite(%s)", path)
	}

	writer, err := sendFile(conn, path, perms, mtime)
	return writer, wrapClientError(err, c, "OpenWrite(%s)", path)
}

// getAttribute returns the first message returned by the server by running
// <host-prefix>:<attr>, where host-prefix is determined from the DeviceDescriptor.
func (c *Device) getAttribute(attr string) (string, error) {
	resp, err := roundTripSingleResponse(c.server,
		fmt.Sprintf("%s:%s", c.descriptor.getHostPrefix(), attr))
	if err != nil {
		return "", err
	}
	return string(resp), nil
}

func (c *Device) getSyncConn() (*wire.SyncConn, error) {
	conn, err := c.dialDevice()
	if err != nil {
		return nil, err
	}

	// Switch the connection to sync mode.
	if err := wire.SendMessageString(conn, "sync:"); err != nil {
		return nil, err
	}
	if _, err := conn.ReadStatus("sync"); err != nil {
		return nil, err
	}

	return conn.NewSyncConn(), nil
}

// dialDevice switches the connection to communicate directly with the device
// by requesting the transport defined by the DeviceDescriptor.
func (c *Device) dialDevice() (*wire.Conn, error) {
	conn, err := c.server.Dial()
	if err != nil {
		return nil, err
	}

	req := fmt.Sprintf("host:%s", c.descriptor.getTransportDescriptor())
	if err = wire.SendMessageString(conn, req); err != nil {
		conn.Close()
		return nil, errors.WrapErrf(err, "error connecting to device '%s'", c.descriptor)
	}

	if _, err = conn.ReadStatus(req); err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

// prepareCommandLine validates the command and argument strings, quotes
// arguments if required, and joins them into a valid adb command string.
func prepareCommandLine(cmd string, args ...string) (string, error) {
	if isBlank(cmd) {
		return "", errors.AssertionErrorf("command cannot be empty")
	}

	for i, arg := range args {
		if strings.ContainsRune(arg, '"') {
			return "", errors.Errorf(errors.ParseError, "arg at index %d contains an invalid double quote: %s", i, arg)
		}
		if containsWhitespace(arg) {
			args[i] = fmt.Sprintf("\"%s\"", arg)
		}
	}

	// Prepend the command to the args array.
	if len(args) > 0 {
		cmd = fmt.Sprintf("%s %s", cmd, strings.Join(args, " "))
	}

	return cmd, nil
}
