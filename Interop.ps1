$code  = @"
/*
From: http://gallery.technet.microsoft.com/scriptcenter/Convert-WindowsImageps1-0fe23a8f
*/

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Xml.Linq;
using System.Xml.XPath;
using Microsoft.Win32.SafeHandles;

namespace WIMInterop {

    /// <summary>
    /// P/Invoke methods and associated enums, flags, and structs.
    /// </summary>
    public class
    NativeMethods {

        #region VHD

        public const Int32 ERROR_SUCCESS = 0;
        public const int OPEN_VIRTUAL_DISK_RW_DEPTH_DEFAULT = 1;
        public const int VIRTUAL_STORAGE_TYPE_DEVICE_ISO = 1;
        public const int VIRTUAL_STORAGE_TYPE_DEVICE_VHD = 2;
        public const int VIRTUAL_STORAGE_TYPE_DEVICE_VHDX = 3;
        public const int CREATE_VIRTUAL_DISK_PARAMETERS_DEFAULT_SECTOR_SIZE = 0x200;
        public static readonly Guid VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT = new Guid("EC984AEC-A0F9-47e9-901F-71415A66345B");

        public enum CREATE_VIRTUAL_DISK_FLAG : int {
            CREATE_VIRTUAL_DISK_FLAG_NONE = 0x00000000,
            CREATE_VIRTUAL_DISK_FLAG_FULL_PHYSICAL_ALLOCATION = 0x00000001
        }

        public enum CREATE_VIRTUAL_DISK_VERSION : int {
            CREATE_VIRTUAL_DISK_VERSION_UNSPECIFIED = 0,
            CREATE_VIRTUAL_DISK_VERSION_1 = 1
        }

        public enum ATTACH_VIRTUAL_DISK_FLAG : int {
            ATTACH_VIRTUAL_DISK_FLAG_NONE = 0x00000000,
            ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY = 0x00000001,
            ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER = 0x00000002,
            ATTACH_VIRTUAL_DISK_FLAG_PERMANENT_LIFETIME = 0x00000004,
            ATTACH_VIRTUAL_DISK_FLAG_NO_LOCAL_HOST = 0x00000008
        }

        public enum ATTACH_VIRTUAL_DISK_VERSION : int {
            ATTACH_VIRTUAL_DISK_VERSION_UNSPECIFIED = 0,
            ATTACH_VIRTUAL_DISK_VERSION_1 = 1
        }

        public enum DETACH_VIRTUAL_DISK_FLAG : int {
            DETACH_VIRTUAL_DISK_FLAG_NONE = 0
        }

        public enum OPEN_VIRTUAL_DISK_FLAG : int {
            OPEN_VIRTUAL_DISK_FLAG_NONE = 0x00000000,
            OPEN_VIRTUAL_DISK_FLAG_NO_PARENTS = 0x00000001,
            OPEN_VIRTUAL_DISK_FLAG_BLANK_FILE = 0x00000002,
            OPEN_VIRTUAL_DISK_FLAG_BOOT_DRIVE = 0x00000004
        }

        public enum OPEN_VIRTUAL_DISK_VERSION : int {
            OPEN_VIRTUAL_DISK_VERSION_1 = 1
        }


        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct ATTACH_VIRTUAL_DISK_PARAMETERS {
            public ATTACH_VIRTUAL_DISK_VERSION Version;
            public ATTACH_VIRTUAL_DISK_PARAMETERS_Version1 Version1;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct ATTACH_VIRTUAL_DISK_PARAMETERS_Version1 {
            public Int32 Reserved;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct OPEN_VIRTUAL_DISK_PARAMETERS {
            public OPEN_VIRTUAL_DISK_VERSION Version;
            public OPEN_VIRTUAL_DISK_PARAMETERS_Version1 Version1;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct OPEN_VIRTUAL_DISK_PARAMETERS_Version1 {
            public Int32 RWDepth;
        }

        public enum VIRTUAL_DISK_ACCESS_MASK : int {
            VIRTUAL_DISK_ACCESS_ATTACH_RO = 0x00010000,
            VIRTUAL_DISK_ACCESS_ATTACH_RW = 0x00020000,
            VIRTUAL_DISK_ACCESS_DETACH = 0x00040000,
            VIRTUAL_DISK_ACCESS_GET_INFO = 0x00080000,
            VIRTUAL_DISK_ACCESS_CREATE = 0x00100000,
            VIRTUAL_DISK_ACCESS_METAOPS = 0x00200000,
            VIRTUAL_DISK_ACCESS_READ = 0x000d0000,
            VIRTUAL_DISK_ACCESS_ALL = 0x003f0000,
            VIRTUAL_DISK_ACCESS_WRITABLE = 0x00320000
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct CREATE_VIRTUAL_DISK_PARAMETERS {
            public CREATE_VIRTUAL_DISK_VERSION Version;
            public CREATE_VIRTUAL_DISK_PARAMETERS_Version1 Version1;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct CREATE_VIRTUAL_DISK_PARAMETERS_Version1 {
            public Guid UniqueId;
            public Int64 MaximumSize;
            public Int32 BlockSizeInBytes;
            public Int32 SectorSizeInBytes;
            public IntPtr ParentPath;
            public IntPtr SourcePath;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct VIRTUAL_STORAGE_TYPE {
            public Int32 DeviceId;
            public Guid VendorId;
        }

        [DllImport("virtdisk.dll", CharSet = CharSet.Unicode)]
        public static extern Int32 AttachVirtualDisk(IntPtr VirtualDiskHandle, IntPtr SecurityDescriptor, ATTACH_VIRTUAL_DISK_FLAG Flags, Int32 ProviderSpecificFlags, ref ATTACH_VIRTUAL_DISK_PARAMETERS Parameters, IntPtr Overlapped);

        [DllImport("virtdisk.dll", CharSet = CharSet.Unicode)]
        public static extern Int32 DetachVirtualDisk(IntPtr VirtualDiskHandle, DETACH_VIRTUAL_DISK_FLAG Flags, Int32 ProviderSpecificFlags);

        [DllImportAttribute("kernel32.dll", SetLastError = true)]
        [return: MarshalAsAttribute(UnmanagedType.Bool)]
        public static extern Boolean CloseHandle(IntPtr hObject);

        [DllImport("virtdisk.dll", CharSet = CharSet.Unicode)]
        public static extern Int32 OpenVirtualDisk(ref VIRTUAL_STORAGE_TYPE VirtualStorageType, String Path, VIRTUAL_DISK_ACCESS_MASK VirtualDiskAccessMask, OPEN_VIRTUAL_DISK_FLAG Flags, ref OPEN_VIRTUAL_DISK_PARAMETERS Parameters, ref IntPtr Handle);

        [DllImport("virtdisk.dll", CharSet = CharSet.Unicode)]
        public static extern Int32 GetVirtualDiskPhysicalPath(IntPtr VirtualDiskHandle,
            ref UInt64 DiskPathSizeInBytes, [Out] StringBuilder DiskPath);

        [DllImport("virtdisk.dll", CharSet = CharSet.Unicode)]
        public static extern Int32 CreateVirtualDisk(ref VIRTUAL_STORAGE_TYPE VirtualStorageType, String Path, VIRTUAL_DISK_ACCESS_MASK VirtualDiskAccessMask, IntPtr SecurityDescriptor, CREATE_VIRTUAL_DISK_FLAG Flags, int ProviderSpecificFlags, ref CREATE_VIRTUAL_DISK_PARAMETERS Parameters, IntPtr Overlapped, ref IntPtr Handle);

        #endregion VHD

        #region Delegates and Callbacks
        #region WIMGAPI

        ///<summary>
        ///User-defined function used with the RegisterMessageCallback or UnregisterMessageCallback function.
        ///</summary>
        ///<param name="MessageId">Specifies the message being sent.</param>
        ///<param name="wParam">Specifies additional message information. The contents of this parameter depend on the value of the
        ///MessageId parameter.</param>
        ///<param name="lParam">Specifies additional message information. The contents of this parameter depend on the value of the
        ///MessageId parameter.</param>
        ///<param name="UserData">Specifies the user-defined value passed to RegisterCallback.</param>
        ///<returns>
        ///To indicate success and to enable other subscribers to process the message return WIM_MSG_SUCCESS.
        ///To prevent other subscribers from receiving the message, return WIM_MSG_DONE.
        ///To cancel an image apply or capture, return WIM_MSG_ABORT_IMAGE when handling the WIM_MSG_PROCESS message.
        ///</returns>
        public delegate uint
        WimMessageCallback(
            uint   MessageId,
            IntPtr wParam,
            IntPtr lParam,
            IntPtr UserData
        );

        public static void
        RegisterMessageCallback(
            WimFileHandle hWim,
            WimMessageCallback callback) {

            uint _callback = NativeMethods.WimRegisterMessageCallback(hWim, callback, IntPtr.Zero);
            int rc = Marshal.GetLastWin32Error();
            if (0 != rc) {
                // Throw an exception if something bad happened on the Win32 end.
                throw
                    new InvalidOperationException(
                        string.Format(
                            CultureInfo.CurrentCulture,
                            "Unable to register message callback."
                ));
            }
        }

        public static void
        UnregisterMessageCallback(
            WimFileHandle hWim,
            WimMessageCallback registeredCallback) {

            bool status = NativeMethods.WimUnregisterMessageCallback(hWim, registeredCallback);
            int rc = Marshal.GetLastWin32Error();
            if (!status) {
                throw
                    new InvalidOperationException(
                        string.Format(
                            CultureInfo.CurrentCulture,
                            "Unable to unregister message callback."
                ));
            }
        }

        #endregion WIMGAPI
        #endregion Delegates and Callbacks

        #region Constants

        #region WIMGAPI

        public   const uint  WIM_FLAG_VERIFY                      = 0x00000002;
        public   const uint  WIM_FLAG_INDEX                       = 0x00000004;

        public   const uint  WM_APP                               = 0x00008000;

        #endregion WIMGAPI

        #endregion Constants

        #region WIMGAPI

        [FlagsAttribute]
        internal enum
        WimCreateFileDesiredAccess
            : uint {
            WimQuery                   = 0x00000000,
            WimGenericRead             = 0x80000000
        }

        /// <summary>
        /// Specifies how the file is to be treated and what features are to be used.
        /// </summary>
        [FlagsAttribute]
        internal enum
        WimApplyFlags
            : uint {
            /// <summary>
            /// No flags.
            /// </summary>
            WimApplyFlagsNone          = 0x00000000,
            /// <summary>
            /// Reserved.
            /// </summary>
            WimApplyFlagsReserved      = 0x00000001,
            /// <summary>
            /// Verifies that files match original data.
            /// </summary>
            WimApplyFlagsVerify        = 0x00000002,
            /// <summary>
            /// Specifies that the image is to be sequentially read for caching or performance purposes.
            /// </summary>
            WimApplyFlagsIndex         = 0x00000004,
            /// <summary>
            /// Applies the image without physically creating directories or files. Useful for obtaining a list of files and directories in the image.
            /// </summary>
            WimApplyFlagsNoApply       = 0x00000008,
            /// <summary>
            /// Disables restoring security information for directories.
            /// </summary>
            WimApplyFlagsNoDirAcl      = 0x00000010,
            /// <summary>
            /// Disables restoring security information for files
            /// </summary>
            WimApplyFlagsNoFileAcl     = 0x00000020,
            /// <summary>
            /// The .wim file is opened in a mode that enables simultaneous reading and writing.
            /// </summary>
            WimApplyFlagsShareWrite    = 0x00000040,
            /// <summary>
            /// Sends a WIM_MSG_FILEINFO message during the apply operation.
            /// </summary>
            WimApplyFlagsFileInfo      = 0x00000080,
            /// <summary>
            /// Disables automatic path fixups for junctions and symbolic links.
            /// </summary>
            WimApplyFlagsNoRpFix       = 0x00000100,
            /// <summary>
            /// Returns a handle that cannot commit changes, regardless of the access level requested at mount time.
            /// </summary>
            WimApplyFlagsMountReadOnly = 0x00000200,
            /// <summary>
            /// Reserved.
            /// </summary>
            WimApplyFlagsMountFast     = 0x00000400,
            /// <summary>
            /// Reserved.
            /// </summary>
            WimApplyFlagsMountLegacy   = 0x00000800
        }

        public enum WimMessage : uint {
            WIM_MSG                    = WM_APP + 0x1476,
            WIM_MSG_TEXT,
            ///<summary>
            ///Indicates an update in the progress of an image application.
            ///</summary>
            WIM_MSG_PROGRESS,
            ///<summary>
            ///Enables the caller to prevent a file or a directory from being captured or applied.
            ///</summary>
            WIM_MSG_PROCESS,
            ///<summary>
            ///Indicates that volume information is being gathered during an image capture.
            ///</summary>
            WIM_MSG_SCANNING,
            ///<summary>
            ///Indicates the number of files that will be captured or applied.
            ///</summary>
            WIM_MSG_SETRANGE,
            ///<summary>
            ///Indicates the number of files that have been captured or applied.
            ///</summary>
            WIM_MSG_SETPOS,
            ///<summary>
            ///Indicates that a file has been either captured or applied.
            ///</summary>
            WIM_MSG_STEPIT,
            ///<summary>
            ///Enables the caller to prevent a file resource from being compressed during a capture.
            ///</summary>
            WIM_MSG_COMPRESS,
            ///<summary>
            ///Alerts the caller that an error has occurred while capturing or applying an image.
            ///</summary>
            WIM_MSG_ERROR,
            ///<summary>
            ///Enables the caller to align a file resource on a particular alignment boundary.
            ///</summary>
            WIM_MSG_ALIGNMENT,
            WIM_MSG_RETRY,
            ///<summary>
            ///Enables the caller to align a file resource on a particular alignment boundary.
            ///</summary>
            WIM_MSG_SPLIT,
            WIM_MSG_SUCCESS            = 0x00000000,
            WIM_MSG_ABORT_IMAGE        = 0xFFFFFFFF
        }

        internal enum
        WimCreationDisposition
            : uint {
            WimOpenExisting            = 0x00000003,
        }

        internal enum
        WimActionFlags
            : uint {
            WimIgnored                 = 0x00000000
        }

        internal enum
        WimCompressionType
            : uint {
            WimIgnored                 = 0x00000000
        }

        internal enum
        WimCreationResult
            : uint {
            WimCreatedNew              = 0x00000000,
            WimOpenedExisting          = 0x00000001
        }

        #endregion WIMGAPI

        #region WIMGAPI P/Invoke

        #region SafeHandle wrappers for WimFileHandle and WimImageHandle

        public sealed class WimFileHandle : SafeHandle {

            public WimFileHandle(
                string wimPath)
                : base(IntPtr.Zero, true) {

                if (String.IsNullOrEmpty(wimPath)) {
                    throw new ArgumentNullException("wimPath");
                }

                if (!File.Exists(Path.GetFullPath(wimPath))) {
                    throw new FileNotFoundException((new FileNotFoundException()).Message, wimPath);
                }

                NativeMethods.WimCreationResult creationResult;

                this.handle = NativeMethods.WimCreateFile(
                    wimPath,
                    NativeMethods.WimCreateFileDesiredAccess.WimGenericRead,
                    NativeMethods.WimCreationDisposition.WimOpenExisting,
                    NativeMethods.WimActionFlags.WimIgnored,
                    NativeMethods.WimCompressionType.WimIgnored,
                    out creationResult
                );

                // Check results.
                if (creationResult != NativeMethods.WimCreationResult.WimOpenedExisting) {
                    throw new Win32Exception();
                }

                if (this.handle == IntPtr.Zero) {
                    throw new Win32Exception();
                }

                // Set the temporary path.
                NativeMethods.WimSetTemporaryPath(
                    this,
                    Environment.ExpandEnvironmentVariables("%TEMP%")
                );
            }

            protected override bool ReleaseHandle() {
                return NativeMethods.WimCloseHandle(this.handle);
            }

            public override bool IsInvalid {
                get { return this.handle == IntPtr.Zero; }
            }
        }

        public sealed class WimImageHandle : SafeHandle {
            public WimImageHandle(
                WimFile Container,
                uint ImageIndex)
                : base(IntPtr.Zero, true) {

                if (null == Container) {
                    throw new ArgumentNullException("Container");
                }

                if ((Container.Handle.IsClosed) || (Container.Handle.IsInvalid)) {
                    throw new ArgumentNullException("The handle to the WIM file has already been closed, or is invalid.", "Container");
                }

                if (ImageIndex > Container.ImageCount) {
                    throw new ArgumentOutOfRangeException("ImageIndex", "The index does not exist in the specified WIM file.");
                }

                this.handle = NativeMethods.WimLoadImage(
                    Container.Handle.DangerousGetHandle(),
                    ImageIndex);
            }

            protected override bool ReleaseHandle() {
                return NativeMethods.WimCloseHandle(this.handle);
            }

            public override bool IsInvalid {
                get { return this.handle == IntPtr.Zero; }
            }
        }

        #endregion SafeHandle wrappers for WimFileHandle and WimImageHandle

        [DllImport("Wimgapi.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "WIMCreateFile")]
        internal static extern IntPtr
        WimCreateFile(
            [In, MarshalAs(UnmanagedType.LPWStr)] string WimPath,
            [In]    WimCreateFileDesiredAccess DesiredAccess,
            [In]    WimCreationDisposition CreationDisposition,
            [In]    WimActionFlags FlagsAndAttributes,
            [In]    WimCompressionType CompressionType,
            [Out, Optional] out WimCreationResult CreationResult
        );

        [DllImport("Wimgapi.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "WIMCloseHandle")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool
        WimCloseHandle(
            [In]    IntPtr Handle
        );

        [DllImport("Wimgapi.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "WIMLoadImage")]
        internal static extern IntPtr
        WimLoadImage(
            [In]    IntPtr Handle,
            [In]    uint ImageIndex
        );

        [DllImport("Wimgapi.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "WIMGetImageCount")]
        internal static extern uint
        WimGetImageCount(
            [In]    WimFileHandle Handle
        );

        [DllImport("Wimgapi.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "WIMApplyImage")]
        internal static extern bool
        WimApplyImage(
            [In]    WimImageHandle Handle,
            [In, Optional, MarshalAs(UnmanagedType.LPWStr)] string Path,
            [In]    WimApplyFlags Flags
        );

        [DllImport("Wimgapi.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "WIMGetImageInformation")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool
        WimGetImageInformation(
            [In]        SafeHandle Handle,
            [Out]   out StringBuilder ImageInfo,
            [Out]   out uint SizeOfImageInfo
        );

        [DllImport("Wimgapi.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "WIMSetTemporaryPath")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool
        WimSetTemporaryPath(
            [In]    WimFileHandle Handle,
            [In]    string TempPath
        );

        [DllImport("Wimgapi.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "WIMRegisterMessageCallback", CallingConvention = CallingConvention.StdCall)]
        internal static extern uint
        WimRegisterMessageCallback(
            [In, Optional] WimFileHandle      hWim,
            [In]           WimMessageCallback MessageProc,
            [In, Optional] IntPtr             ImageInfo
        );

        [DllImport("Wimgapi.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "WIMUnregisterMessageCallback", CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool
        WimUnregisterMessageCallback(
            [In, Optional] WimFileHandle      hWim,
            [In]           WimMessageCallback MessageProc
        );

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern uint GetLogicalDriveStrings(uint bufferLength, [Out] char[] buffer);

        #endregion WIMGAPI P/Invoke
    }

    #region WIM Interop

    public class WimFile {

        internal XDocument m_xmlInfo;
        internal List<WimImage> m_imageList;

        private static NativeMethods.WimMessageCallback wimMessageCallback;

        #region Events

        /// <summary>
        /// DefaultImageEvent handler
        /// </summary>
        public delegate void DefaultImageEventHandler(object sender, DefaultImageEventArgs e);

        ///<summary>
        ///ProcessFileEvent handler
        ///</summary>
        public delegate void ProcessFileEventHandler(object sender, ProcessFileEventArgs e);

        ///<summary>
        ///Enable the caller to prevent a file resource from being compressed during a capture.
        ///</summary>
        public event ProcessFileEventHandler ProcessFileEvent;

        ///<summary>
        ///Indicate an update in the progress of an image application.
        ///</summary>
        public event DefaultImageEventHandler ProgressEvent;

        ///<summary>
        ///Alert the caller that an error has occurred while capturing or applying an image.
        ///</summary>
        public event DefaultImageEventHandler ErrorEvent;

        ///<summary>
        ///Indicate that a file has been either captured or applied.
        ///</summary>
        public event DefaultImageEventHandler StepItEvent;

        ///<summary>
        ///Indicate the number of files that will be captured or applied.
        ///</summary>
        public event DefaultImageEventHandler SetRangeEvent;

        ///<summary>
        ///Indicate the number of files that have been captured or applied.
        ///</summary>
        public event DefaultImageEventHandler SetPosEvent;

        #endregion Events

        private
        enum
        ImageEventMessage : uint {
            ///<summary>
            ///Enables the caller to prevent a file or a directory from being captured or applied.
            ///</summary>
            Progress = NativeMethods.WimMessage.WIM_MSG_PROGRESS,
            ///<summary>
            ///Notification sent to enable the caller to prevent a file or a directory from being captured or applied.
            ///To prevent a file or a directory from being captured or applied, call WindowsImageContainer.SkipFile().
            ///</summary>
            Process = NativeMethods.WimMessage.WIM_MSG_PROCESS,
            ///<summary>
            ///Enables the caller to prevent a file resource from being compressed during a capture.
            ///</summary>
            Compress = NativeMethods.WimMessage.WIM_MSG_COMPRESS,
            ///<summary>
            ///Alerts the caller that an error has occurred while capturing or applying an image.
            ///</summary>
            Error = NativeMethods.WimMessage.WIM_MSG_ERROR,
            ///<summary>
            ///Enables the caller to align a file resource on a particular alignment boundary.
            ///</summary>
            Alignment = NativeMethods.WimMessage.WIM_MSG_ALIGNMENT,
            ///<summary>
            ///Enables the caller to align a file resource on a particular alignment boundary.
            ///</summary>
            Split = NativeMethods.WimMessage.WIM_MSG_SPLIT,
            ///<summary>
            ///Indicates that volume information is being gathered during an image capture.
            ///</summary>
            Scanning = NativeMethods.WimMessage.WIM_MSG_SCANNING,
            ///<summary>
            ///Indicates the number of files that will be captured or applied.
            ///</summary>
            SetRange = NativeMethods.WimMessage.WIM_MSG_SETRANGE,
            ///<summary>
            ///Indicates the number of files that have been captured or applied.
            /// </summary>
            SetPos = NativeMethods.WimMessage.WIM_MSG_SETPOS,
            ///<summary>
            ///Indicates that a file has been either captured or applied.
            ///</summary>
            StepIt = NativeMethods.WimMessage.WIM_MSG_STEPIT,
            ///<summary>
            ///Success.
            ///</summary>
            Success = NativeMethods.WimMessage.WIM_MSG_SUCCESS,
            ///<summary>
            ///Abort.
            ///</summary>
            Abort = NativeMethods.WimMessage.WIM_MSG_ABORT_IMAGE
        }

        ///<summary>
        ///Event callback to the Wimgapi events
        ///</summary>
        private
        uint
        ImageEventMessagePump(
            uint MessageId,
            IntPtr wParam,
            IntPtr lParam,
            IntPtr UserData) {

            uint status = (uint) NativeMethods.WimMessage.WIM_MSG_SUCCESS;

            DefaultImageEventArgs eventArgs = new DefaultImageEventArgs(wParam, lParam, UserData);

            switch ((ImageEventMessage)MessageId) {

                case ImageEventMessage.Progress:
                    ProgressEvent(this, eventArgs);
                    break;

                case ImageEventMessage.Process:
                    if (null != ProcessFileEvent) {
                        string fileToImage = Marshal.PtrToStringUni(wParam);
                        ProcessFileEventArgs fileToProcess = new ProcessFileEventArgs(fileToImage, lParam);
                        ProcessFileEvent(this, fileToProcess);

                        if (fileToProcess.Abort == true) {
                            status = (uint)ImageEventMessage.Abort;
                        }
                    }
                    break;

                case ImageEventMessage.Error:
                    if (null != ErrorEvent) {
                        ErrorEvent(this, eventArgs);
                    }
                    break;

                case ImageEventMessage.SetRange:
                    if (null != SetRangeEvent) {
                        SetRangeEvent(this, eventArgs);
                    }
                    break;

                case ImageEventMessage.SetPos:
                    if (null != SetPosEvent) {
                        SetPosEvent(this, eventArgs);
                    }
                    break;

                case ImageEventMessage.StepIt:
                    if (null != StepItEvent) {
                        StepItEvent(this, eventArgs);
                    }
                    break;

                default:
                    break;
            }
            return status;

        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="wimPath">Path to the WIM container.</param>
        public
        WimFile(string wimPath) {
            if (string.IsNullOrEmpty(wimPath)) {
                throw new ArgumentNullException("wimPath");
            }

            if (!File.Exists(Path.GetFullPath(wimPath))) {
                throw new FileNotFoundException((new FileNotFoundException()).Message, wimPath);
            }

            Handle = new NativeMethods.WimFileHandle(wimPath);

            // Hook up the events before we return.
            //wimMessageCallback = new NativeMethods.WimMessageCallback(ImageEventMessagePump);
            //NativeMethods.RegisterMessageCallback(this.Handle, wimMessageCallback);
        }

        /// <summary>
        /// Closes the WIM file.
        /// </summary>
        public void
        Close() {
            foreach (WimImage image in Images) {
                image.Close();
            }

            if (null != wimMessageCallback) {
                NativeMethods.UnregisterMessageCallback(this.Handle, wimMessageCallback);
                wimMessageCallback = null;
            }

            if ((!Handle.IsClosed) && (!Handle.IsInvalid)) {
                Handle.Close();
            }
        }

        /// <summary>
        /// Provides a list of WimImage objects, representing the images in the WIM container file.
        /// </summary>
        public List<WimImage>
        Images {
            get {
                if (null == m_imageList) {

                    int imageCount = (int)ImageCount;
                    m_imageList = new List<WimImage>(imageCount);
                    for (int i = 0; i < imageCount; i++) {

                        // Load up each image so it's ready for us.
                        m_imageList.Add(
                            new WimImage(this, (uint)i + 1));
                    }
                }

                return m_imageList;
            }
        }

        /// <summary>
        /// Provides a list of names of the images in the specified WIM container file.
        /// </summary>
        public List<string>
        ImageNames {
            get {
                List<string> nameList = new List<string>();
                foreach (WimImage image in Images) {
                    nameList.Add(image.ImageName);
                }
                return nameList;
            }
        }

        /// <summary>
        /// Indexer for WIM images inside the WIM container, indexed by the image number.
        /// The list of Images is 0-based, but the WIM container is 1-based, so we automatically compensate for that.
        /// this[1] returns the 0th image in the WIM container.
        /// </summary>
        /// <param name="ImageIndex">The 1-based index of the image to retrieve.</param>
        /// <returns>WinImage object.</returns>
        public WimImage
        this[int ImageIndex] {
            get { return Images[ImageIndex - 1]; }
        }

        /// <summary>
        /// Indexer for WIM images inside the WIM container, indexed by the image name.
        /// WIMs created by different processes sometimes contain different information - including the name.
        /// Some images have their name stored in the Name field, some in the Flags field, and some in the EditionID field.
        /// We take all of those into account in while searching the WIM.
        /// </summary>
        /// <param name="ImageName"></param>
        /// <returns></returns>
        public WimImage
        this[string ImageName] {
            get {
                return
                    Images.Where(i => (
                        i.ImageName.ToUpper()  == ImageName.ToUpper() ||
                        i.ImageFlags.ToUpper() == ImageName.ToUpper() ))
                    .DefaultIfEmpty(null)
                        .FirstOrDefault<WimImage>();
            }
        }

        /// <summary>
        /// Returns the number of images in the WIM container.
        /// </summary>
        internal uint
        ImageCount {
            get { return NativeMethods.WimGetImageCount(Handle); }
        }

        /// <summary>
        /// Returns an XDocument representation of the XML metadata for the WIM container and associated images.
        /// </summary>
        internal XDocument
        XmlInfo {
            get {

                if (null == m_xmlInfo) {
                    StringBuilder builder;
                    uint bytes;
                    if (!NativeMethods.WimGetImageInformation(Handle, out builder, out bytes)) {
                        throw new Win32Exception();
                    }

                    // Ensure the length of the returned bytes to avoid garbage characters at the end.
                    int charCount = (int)bytes / sizeof(char);
                    if (null != builder) {
                        // Get rid of the unicode file marker at the beginning of the XML.
                        builder.Remove(0, 1);
                        builder.EnsureCapacity(charCount - 1);
                        builder.Length = charCount - 1;

                        // This isn't likely to change while we have the image open, so cache it.
                        m_xmlInfo = XDocument.Parse(builder.ToString().Trim());
                    } else {
                        m_xmlInfo = null;
                    }
                }

                return m_xmlInfo;
            }
        }

        public NativeMethods.WimFileHandle Handle {
            get;
            private set;
        }
    }

    public class
    WimImage {

        internal XDocument m_xmlInfo;

        public
        WimImage(
            WimFile Container,
            uint ImageIndex) {

            if (null == Container) {
                throw new ArgumentNullException("Container");
            }

            if ((Container.Handle.IsClosed) || (Container.Handle.IsInvalid)) {
                throw new ArgumentNullException("The handle to the WIM file has already been closed, or is invalid.", "Container");
            }

            if (ImageIndex > Container.ImageCount) {
                throw new ArgumentOutOfRangeException("ImageIndex", "The index does not exist in the specified WIM file.");
            }

            Handle = new NativeMethods.WimImageHandle(Container, ImageIndex);
        }

        public enum
        Architectures : uint {
            x86   = 0x0,
            ARM   = 0x5,
            IA64  = 0x6,
            AMD64 = 0x9
        }

        public void
        Close() {
            if ((!Handle.IsClosed) && (!Handle.IsInvalid)) {
                Handle.Close();
            }
        }

        public void
        Apply(
            string ApplyToPath) {

            if (string.IsNullOrEmpty(ApplyToPath)) {
                throw new ArgumentNullException("ApplyToPath");
            }

            ApplyToPath = Path.GetFullPath(ApplyToPath);

            if (!Directory.Exists(ApplyToPath)) {
                throw new DirectoryNotFoundException("The WIM cannot be applied because the specified directory was not found.");
            }

            if (!NativeMethods.WimApplyImage(
                this.Handle,
                ApplyToPath,
                NativeMethods.WimApplyFlags.WimApplyFlagsNone
            )) {
                throw new Win32Exception();
            }
        }

        public NativeMethods.WimImageHandle
        Handle {
            get;
            private set;
        }

        internal XDocument
        XmlInfo {
            get {

                if (null == m_xmlInfo) {
                    StringBuilder builder;
                    uint bytes;
                    if (!NativeMethods.WimGetImageInformation(Handle, out builder, out bytes)) {
                        throw new Win32Exception();
                    }

                    // Ensure the length of the returned bytes to avoid garbage characters at the end.
                    int charCount = (int)bytes / sizeof(char);
                    if (null != builder) {
                        // Get rid of the unicode file marker at the beginning of the XML.
                        builder.Remove(0, 1);
                        builder.EnsureCapacity(charCount - 1);
                        builder.Length = charCount - 1;

                        // This isn't likely to change while we have the image open, so cache it.
                        m_xmlInfo = XDocument.Parse(builder.ToString().Trim());
                    } else {
                        m_xmlInfo = null;
                    }
                }

                return m_xmlInfo;
            }
        }

        public string
        ImageIndex {
            get { return XmlInfo.Element("IMAGE").Attribute("INDEX").Value; }
        }

        public string
        ImageName {
            get { return XmlInfo.XPathSelectElement("/IMAGE/NAME").Value; }
        }

        public string
        ImageEditionId {
            get { return XmlInfo.XPathSelectElement("/IMAGE/WINDOWS/EDITIONID").Value; }
        }

        public string
        ImageFlags {
            get { return XmlInfo.XPathSelectElement("/IMAGE/FLAGS").Value; }
        }

        public string
        ImageProductType {
            get {
                return XmlInfo.XPathSelectElement("/IMAGE/WINDOWS/PRODUCTTYPE").Value;
            }
        }

        public string
        ImageInstallationType {
            get { return XmlInfo.XPathSelectElement("/IMAGE/WINDOWS/INSTALLATIONTYPE").Value; }
        }

        public string
        ImageDescription {
            get { return XmlInfo.XPathSelectElement("/IMAGE/DESCRIPTION").Value; }
        }

        public ulong
        ImageSize {
            get { return ulong.Parse(XmlInfo.XPathSelectElement("/IMAGE/TOTALBYTES").Value); }
        }

        public Architectures
        ImageArchitecture {
            get {
                int arch = -1;
                try {
                    arch = int.Parse(XmlInfo.XPathSelectElement("/IMAGE/WINDOWS/ARCH").Value);
                } catch { }

                return (Architectures)arch;
            }
        }

        public string
        ImageDefaultLanguage {
            get {
                string lang = null;
                try {
                    lang = XmlInfo.XPathSelectElement("/IMAGE/WINDOWS/LANGUAGES/DEFAULT").Value;
                } catch { }

                return lang;
            }
        }

        public Version
        ImageVersion {
            get {
                int major = 0;
                int minor = 0;
                int build = 0;
                int revision = 0;

                try {
                    major = int.Parse(XmlInfo.XPathSelectElement("/IMAGE/WINDOWS/VERSION/MAJOR").Value);
                    minor = int.Parse(XmlInfo.XPathSelectElement("/IMAGE/WINDOWS/VERSION/MINOR").Value);
                    build = int.Parse(XmlInfo.XPathSelectElement("/IMAGE/WINDOWS/VERSION/BUILD").Value);
                    revision = int.Parse(XmlInfo.XPathSelectElement("/IMAGE/WINDOWS/VERSION/SPBUILD").Value);
                } catch { }

                return (new Version(major, minor, build, revision));
            }
        }

        public string
        ImageDisplayName {
            get { return XmlInfo.XPathSelectElement("/IMAGE/DISPLAYNAME").Value; }
        }

        public string
        ImageDisplayDescription {
            get { return XmlInfo.XPathSelectElement("/IMAGE/DISPLAYDESCRIPTION").Value; }
        }
    }

    ///<summary>
    ///Describes the file that is being processed for the ProcessFileEvent.
    ///</summary>
    public class
    DefaultImageEventArgs : EventArgs {
        ///<summary>
        ///Default constructor.
        ///</summary>
        public
        DefaultImageEventArgs(
            IntPtr wideParameter,
            IntPtr leftParameter,
            IntPtr userData) {

            WideParameter = wideParameter;
            LeftParameter = leftParameter;
            UserData      = userData;
        }

        ///<summary>
        ///wParam
        ///</summary>
        public IntPtr WideParameter {
            get;
            private set;
        }

        ///<summary>
        ///lParam
        ///</summary>
        public IntPtr LeftParameter {
            get;
            private set;
        }

        ///<summary>
        ///UserData
        ///</summary>
        public IntPtr UserData {
            get;
            private set;
        }
    }

    ///<summary>
    ///Describes the file that is being processed for the ProcessFileEvent.
    ///</summary>
    public class
    ProcessFileEventArgs : EventArgs {
        ///<summary>
        ///Default constructor.
        ///</summary>
        ///<param name="file">Fully qualified path and file name. For example: c:\file.sys.</param>
        ///<param name="skipFileFlag">Default is false - skip file and continue.
        ///Set to true to abort the entire image capture.</param>
        public
        ProcessFileEventArgs(
            string file,
            IntPtr skipFileFlag) {

            m_FilePath = file;
            m_SkipFileFlag = skipFileFlag;
        }

        ///<summary>
        ///Skip file from being imaged.
        ///</summary>
        public void
        SkipFile() {
            byte[] byteBuffer = {
                    0
            };
            int byteBufferSize = byteBuffer.Length;
            Marshal.Copy(byteBuffer, 0, m_SkipFileFlag, byteBufferSize);
        }

        ///<summary>
        ///Fully qualified path and file name.
        ///</summary>
        public string
        FilePath {
            get {
                string stringToReturn = "";
                if (m_FilePath != null) {
                    stringToReturn = m_FilePath;
                }
                return stringToReturn;
            }
        }

        ///<summary>
        ///Flag to indicate if the entire image capture should be aborted.
        ///Default is false - skip file and continue. Setting to true will
        ///abort the entire image capture.
        ///</summary>
        public bool Abort {
            set { m_Abort = value; }
            get { return m_Abort;  }
        }

        private string m_FilePath;
        private bool m_Abort;
        private IntPtr m_SkipFileFlag;
    }

    #endregion WIM Interop

    public class VirtualDisk: IDisposable
    {
        private IntPtr handle;
        private bool readOnly;

        private VirtualDisk(IntPtr handle, bool readOnly)
        {
            this.handle = handle;
            this.readOnly = readOnly;
        }

        public static VirtualDisk OpenVirtualDisk(string diskPath)
        {
            IntPtr handle = IntPtr.Zero;

            var openParameters = new NativeMethods.OPEN_VIRTUAL_DISK_PARAMETERS();
            openParameters.Version = NativeMethods.OPEN_VIRTUAL_DISK_VERSION.OPEN_VIRTUAL_DISK_VERSION_1;
            openParameters.Version1.RWDepth = NativeMethods.OPEN_VIRTUAL_DISK_RW_DEPTH_DEFAULT;

            var openStorageType = new NativeMethods.VIRTUAL_STORAGE_TYPE();
            openStorageType.VendorId = NativeMethods.VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT;

            var accessMask = NativeMethods.VIRTUAL_DISK_ACCESS_MASK.VIRTUAL_DISK_ACCESS_ALL;
            bool readOnly = false;

            var ext = Path.GetExtension(diskPath).Substring(1).ToUpper();
            switch(ext)
            {
                case "ISO":
                    openStorageType.DeviceId = NativeMethods.VIRTUAL_STORAGE_TYPE_DEVICE_ISO;
                    accessMask = NativeMethods.VIRTUAL_DISK_ACCESS_MASK.VIRTUAL_DISK_ACCESS_READ;
                    readOnly = true;
                    break;
                case "VHD":
                    openStorageType.DeviceId = NativeMethods.VIRTUAL_STORAGE_TYPE_DEVICE_VHD;
                    break;
                case "VHDX":
                    // TODO: handle v2
                    openStorageType.DeviceId = NativeMethods.VIRTUAL_STORAGE_TYPE_DEVICE_VHDX;
                    break;
                default:
                    throw new Exception("Unrecognized file format: " + ext);
            }

            int openResult = NativeMethods.OpenVirtualDisk(ref openStorageType, diskPath, accessMask, NativeMethods.OPEN_VIRTUAL_DISK_FLAG.OPEN_VIRTUAL_DISK_FLAG_NONE, ref openParameters, ref handle);
            if (openResult != NativeMethods.ERROR_SUCCESS)
            {
                throw new Win32Exception(openResult);
            }

            return new VirtualDisk(handle, readOnly);
        }

        public static VirtualDisk CreateVirtualDisk(string diskPath, UInt64 size, bool expandable=true)
        {
            IntPtr handle = IntPtr.Zero;

            var parameters = new NativeMethods.CREATE_VIRTUAL_DISK_PARAMETERS();
            parameters.Version = NativeMethods.CREATE_VIRTUAL_DISK_VERSION.CREATE_VIRTUAL_DISK_VERSION_1;
            parameters.Version1.BlockSizeInBytes = 0;
            parameters.Version1.MaximumSize = (long)size;
            parameters.Version1.ParentPath = IntPtr.Zero;
            parameters.Version1.SectorSizeInBytes = NativeMethods.CREATE_VIRTUAL_DISK_PARAMETERS_DEFAULT_SECTOR_SIZE;
            parameters.Version1.SourcePath = IntPtr.Zero;
            parameters.Version1.UniqueId = Guid.Empty;

            var storageType = new NativeMethods.VIRTUAL_STORAGE_TYPE();
            storageType.DeviceId = NativeMethods.VIRTUAL_STORAGE_TYPE_DEVICE_VHD;
            storageType.VendorId = NativeMethods.VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT;

            var flags = expandable ? NativeMethods.CREATE_VIRTUAL_DISK_FLAG.CREATE_VIRTUAL_DISK_FLAG_NONE : NativeMethods.CREATE_VIRTUAL_DISK_FLAG.CREATE_VIRTUAL_DISK_FLAG_FULL_PHYSICAL_ALLOCATION;
            int res = NativeMethods.CreateVirtualDisk(ref storageType, diskPath, NativeMethods.VIRTUAL_DISK_ACCESS_MASK.VIRTUAL_DISK_ACCESS_ALL, IntPtr.Zero, flags, 0, ref parameters, IntPtr.Zero, ref handle);
            if (res != NativeMethods.ERROR_SUCCESS)
            {
                throw new Win32Exception(res);
            }

            return new VirtualDisk(handle, false);
        }

        public void Close()
        {
            if(this.handle != IntPtr.Zero)
                NativeMethods.CloseHandle(this.handle);
            this.handle = IntPtr.Zero;
        }

        public void Dispose()
        {
            Close();
        }

        ~VirtualDisk()
        {
            Dispose();
        }

        public void AttachVirtualDisk()
        {
            var attachParameters = new NativeMethods.ATTACH_VIRTUAL_DISK_PARAMETERS();
            attachParameters.Version = NativeMethods.ATTACH_VIRTUAL_DISK_VERSION.ATTACH_VIRTUAL_DISK_VERSION_1;

            var flags = NativeMethods.ATTACH_VIRTUAL_DISK_FLAG.ATTACH_VIRTUAL_DISK_FLAG_PERMANENT_LIFETIME;
            if(this.readOnly)
                flags |= NativeMethods.ATTACH_VIRTUAL_DISK_FLAG.ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY;

            int attachResult = NativeMethods.AttachVirtualDisk(this.handle, IntPtr.Zero, flags, 0, ref attachParameters, IntPtr.Zero);
            if (attachResult != NativeMethods.ERROR_SUCCESS)
            {
                throw new Win32Exception(attachResult);
            }
        }

        public void DetachVirtualDisk()
        {
            int res = NativeMethods.DetachVirtualDisk(this.handle, NativeMethods.DETACH_VIRTUAL_DISK_FLAG.DETACH_VIRTUAL_DISK_FLAG_NONE, 0);
            if (res != NativeMethods.ERROR_SUCCESS)
            {
                throw new Win32Exception(res);
            }

        }

        public string GetVirtualDiskPhysicalPath()
        {
            UInt64 size = 1024;
            var buffer = new StringBuilder((int)size);
            var res = NativeMethods.GetVirtualDiskPhysicalPath(this.handle, ref size, buffer);
            if (res != NativeMethods.ERROR_SUCCESS)
            {
                throw new Win32Exception(res);
            }

            return buffer.ToString();
        }
    }

    public class WinUtils
    {
        public static IList<string> GetLogicalDriveStrings()
        {
            const int size = 512;
            char[] buffer = new char[size];
            uint code = NativeMethods.GetLogicalDriveStrings(size, buffer);
            if (code == 0)
            {
                throw new Win32Exception();
            }

            var list = new List<string>();
            int start = 0;
            for (int i = 0;  i < code;  ++i)
            {
                if (buffer[i] == 0)
                {
                    string s = new string(buffer, start, i - start);
                    list.Add(s);
                    start = i + 1;
                }
            }
            return list;
        }
    }
}
"@

if (-not ([System.Management.Automation.PSTypeName]'WIMInterop.WimFile').Type)
{
    Add-Type -TypeDefinition $code -ReferencedAssemblies "System.Xml","System.Linq","System.Xml.Linq"
}

