/*
    Author: Michal Pitaniello
    Description: An project to cover the functionality of WASAPI topology. 
        By default, will scan for the default audio device(s) and print
        out the device name and its status. Command line variables allow
        the for extended behavior.

    Last Modified: 08/26/2017
*/

#define WIN32_LEAN_AND_MEAN
#define VC_EXTRALEAN

#include <Windows.h>
#include <Winerror.h>
#include <VersionHelpers.h>
#include <mmdeviceapi.h>
#include <Strmif.h>
#include <Endpointvolume.h>
#include <Audiopolicy.h>
#include <Mfidl.h>
#include <functiondiscoverykeys_devpkey.h>
#include <iostream>


//*****************************************************************************
//  Macros
//*****************************************************************************
// https://msdn.microsoft.com/en-us/library/windows/desktop/dd368250(v=vs.85).aspx
#define AUDCLNT_S_NO_SINGLE_PROCESS AUDCLNT_SUCCESS (0x00d)


//*****************************************************************************
//  Class Declarations
//*****************************************************************************
// Helper class to better control output tabbing throughout the program
class Tabs
{
    public:
        Tabs()
        {
            start = tabs;
        }

        Tabs( int i )
        {
            tabs = i;
            start = i;
        }

        Tabs( const Tabs & ) = delete;

        ~Tabs( )
        {
            tabs = start;
        }

        void Inc()
        {
            tabs++;
        }

        void Dec()
        {
            if ( tabs > 0 )
            {
                tabs--;
            }
        }

        int Count() const
        {
            return tabs;
        }

        const char * GetToken( ) const
        {
            return TAB_TOKEN;
        }

    private:
        static int tabs;
        int start;
        static const char *TAB_TOKEN;
};
int Tabs::tabs = 0;
const char *Tabs::TAB_TOKEN = "   ";


// Helper class to let me overload the ostream for windows HRESULT
class MyResult
{
    public:
        MyResult()
        {
            _result = S_OK;
        }

        MyResult( HRESULT res )
        {
            _result = res;
        }

        ~MyResult() 
        {
        }

        MyResult( MyResult &other )
        {
            _result = other._result;
        }

        MyResult & operator=( HRESULT rhs )
        {
            _result = rhs;
            return *this;
        }

        MyResult & operator=( MyResult & rhs )
        {
            if ( &rhs != this )
            {
                _result = rhs._result;
            }
            return *this;
        }

        bool operator<( const MyResult& rhs )
        {
            return _result < rhs._result;
        }

        bool operator>( const MyResult& rhs )
        {
            return rhs._result < _result;
        }

        bool operator<=( const MyResult& rhs )
        {
            return !( _result > rhs._result );
        }

        bool operator>=( const MyResult& rhs )
        {
            return !( _result < rhs._result );
        }

        bool operator==( const MyResult& rhs )
        {
            return _result == rhs._result;
        }

        bool operator!=( const MyResult& rhs )
        {
            return !( _result == rhs._result );
        }

        HRESULT GetResult( ) const
        {
            return _result;
        }

    private:
        HRESULT _result;
};


//*****************************************************************************
//  ostream Overloads
//*****************************************************************************
template < typename  GenericOstream >
GenericOstream & operator<<( GenericOstream &gos, const MyResult &error )
{
    LPSTR errorText = NULL;

    FormatMessageA( FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL,
                   error.GetResult(),
                   MAKELANGID( LANG_NEUTRAL, SUBLANG_DEFAULT ),
                   reinterpret_cast< LPSTR >( &errorText ),
                   0,
                   NULL);

    if ( NULL != errorText )
    {
        std::cout << std::hex
            << "0x"
            << std::uppercase
            << error.GetResult()
            << ": "
            << std::dec
            << errorText;

        LocalFree(errorText);
        errorText = NULL;
    }
    else
    {
        std::cout << "Failed to format error message for error \"0x"
            << std::hex
            << std::uppercase
            << error.GetResult()
            << std::dec
            << "\". Encountered error \"0x"
            << std::hex
            << std::uppercase
            << GetLastError()
            << std::dec
            << "\" during conversion.";
    }

    return gos;
}

template < typename  GenericOstream >
GenericOstream & operator<<( GenericOstream &gos, const VARTYPE  &varType )
{
    switch ( varType )
    {
        case VARENUM::VT_EMPTY:
            gos << "Not specified.";
            break;
        case VARENUM::VT_NULL:
            gos << "NULL.";
            break;
        case VARENUM::VT_I2:
            gos << "2-byte signed int";
            break;
        case VARENUM::VT_I4:
            gos << "4-byte signed int";
            break;
        case VARENUM::VT_R4:
            gos << "4 byte signed real";
            break;
        case VARENUM::VT_R8:
            gos << "8 byte signed real";
            break;
        case VARENUM::VT_CY:
            gos << "currency";
            break;
        case VARENUM::VT_DATE:
            gos << "date";
            break;
        case VARENUM::VT_BSTR:
            gos << "binary string";
            break;
        case VARENUM::VT_DISPATCH:
            gos << "IDIspatch *";
            break;
        case VARENUM::VT_ERROR:
            gos << "Error Code";
            break;
        case VARENUM::VT_BOOL:
            gos << "Boolean";
            break;
        case VARENUM::VT_VARIANT:
            gos << "VARIANT *";
            break;
        case VARENUM::VT_UNKNOWN:
            gos << "IUnknown *";
            break;
        case VARENUM::VT_DECIMAL:
            gos << "16 byte fixed point decimal";
            break;
        case VARENUM::VT_RECORD:
            gos << "User defiend type";
            break;
        case VARENUM::VT_I1:
            gos << "signed char";
            break;
        case VARENUM::VT_UI1:
            gos << "unsigned char";
            break;
        case VARENUM::VT_UI2:
            gos << "unsigned short";
            break;
        case VARENUM::VT_UI4:
            gos << "ULONG";
            break;
        case VARENUM::VT_INT:
            gos << "machine defined signed int";
            break;
        case VARENUM::VT_UINT:
            gos << "machined defined unsigned int";
            break;
        case VARENUM::VT_ARRAY:
            gos << "SAFEARRAY *";
            break;
        case VARENUM::VT_BYREF:
            gos << "void * (for local use)";
            break;
        default:
            gos << "Unkown type";
            break;
    }

    return gos;
}

template < typename  GenericOstream >
GenericOstream & operator<<( GenericOstream &gos, const wchar_t *wstr )
{
    HRESULT result = S_OK;
    size_t origsize = wcslen( wstr ) + 1;
    size_t convertedChars = 0;
    const size_t newsize = origsize*2;
    char *nstring = new char[newsize];
    result = wcstombs_s( &convertedChars, nstring, newsize, wstr, _TRUNCATE );
    if ( SUCCEEDED( result ) )
    {
        gos << nstring;
    }
    else
    {
        gos << "Failed to convert given Unicode string to ANSII.";
    }
    delete [] nstring;

    return gos;
}


template < typename  GenericOstream >
GenericOstream & operator<<( GenericOstream &gos, const Tabs &tabs )
{
    for ( int i = 0; i < tabs.Count(); i++ )
    {
        gos << tabs.GetToken();
    }

    return gos;
}


template < typename GenericOstream >
GenericOstream & operator<<( GenericOstream &gos, const SYSTEMTIME &systemTime )
{
    gos << systemTime.wDayOfWeek
        << " - "
        << systemTime.wDay
        << ", "
        << systemTime.wMonth
        << ", "
        << systemTime.wYear
        << " - {"
        << systemTime.wHour
        << ":"
        << systemTime.wMinute
        << ":"
        << systemTime.wSecond
        << ":"
        << systemTime.wMilliseconds
        << "}";

    return gos;
}


template < typename GenericOstream >
GenericOstream & operator<<( GenericOstream &gos, const GUID &guid )
{
    gos << std::hex
        << "{"
        << guid.Data1
        << "-"
        << guid.Data2
        << "-"
        << guid.Data3
        << "-"
        << static_cast< unsigned short >( guid.Data4[0] )
        << static_cast< unsigned short >( guid.Data4[1] )
        << "-"
        << static_cast< unsigned short >( guid.Data4[2] )
        << static_cast< unsigned short >( guid.Data4[3] )
        << static_cast< unsigned short >( guid.Data4[4] )
        << static_cast< unsigned short >( guid.Data4[5] )
        << static_cast< unsigned short >( guid.Data4[6] )
        << static_cast< unsigned short >( guid.Data4[7] )
        << "}"
        << std::dec;

    return gos;
}


template < typename GenericOstream >
GenericOstream & operator<<( GenericOstream &gos, const DataFlow &direction )
{
    switch( direction )
    {
        case In:
            gos << "In";
            break;

        case Out:
            gos << "Out";
            break;

        default:
            gos << "Unknown Direction";
            break;
    }

    return gos;
}


template < typename GenericOstream >
GenericOstream & operator<<( GenericOstream &gos, const ConnectorType &type )
{
    switch ( type )
    {
        case Unknown_Connector:
            gos << "Unknown Connector";
            break;

        case Physical_Internal:
            gos << "Physical Internal";
            break;

        case Physical_External:
            gos << "Physical External";
            break;

        case Software_IO:
            gos << "Software IO";
            break;

        case Software_Fixed:
            gos << "Software Fixed";
            break;

        case Network:
            gos << "Network";
            break;

        default:
            gos << "Unknown Connection Enumeration";
            break;
    }

    return gos;
}


template < typename GenericOstream >
GenericOstream & operator<<( GenericOstream &gos, const PartType &partType )
{
    switch( partType )
    {
        case Connector:
            gos << "Connector";
            break;

        case Subunit:
            gos << "Subunit";
            break;

        default:
            gos << "Unknown Part Type";
            break;
    }

    return gos;
}


template < typename GenericOstream >
GenericOstream & operator<<( GenericOstream &gos, const PROPERTYKEY &propertyKey )
{
    gos << "("
        << propertyKey.pid
        << ")."
        << propertyKey.fmtid;

    return gos;
}


template < typename GenericOstream >
GenericOstream & operator<<( GenericOstream &gos, const AudioSessionState &audioSessionState )
{
    switch ( audioSessionState )
    {
        case AudioSessionState::AudioSessionStateInactive:
            gos << "The audio session is inactive. (It contains at least one stream, but none of the streams in the session is currently running.)";
            break;
        case AudioSessionState::AudioSessionStateActive:
            gos << "The audio session is active. (At least one of the streams in the session is running.)";
            break;
        case AudioSessionState::AudioSessionStateExpired:
            gos << "The audio session has expired. (It contains no streams.)";
            break;
        default:
            gos << "Unkown audio session state";
            break;
    }
    return gos;
}


template < typename GenericOstream >
GenericOstream & operator<<( GenericOstream &gos, const PIN_DIRECTION &pinDirection )
{
    switch ( pinDirection )
    {
        case PIN_DIRECTION::PINDIR_INPUT:
            gos << "Input pin.";
            break;
        case PIN_DIRECTION::PINDIR_OUTPUT:
            gos << "Output pin.";
            break;
        default:
            gos << "Unkown pin direction.";
            break;
    }

    return gos;
}


template < typename GenericOstream >
GenericOstream & operator<<( GenericOstream &gos, const FILTER_STATE  &filterState )
{
    switch ( filterState )
    {
        case FILTER_STATE::State_Stopped:
            gos << "Stopped. The filter is not processing data.";
            break;
        case FILTER_STATE::State_Paused:
            gos << "Paused. The filter is processing data, but not rendering it.";
            break;
        case FILTER_STATE::State_Running:
            gos << "Running. The filter is processing and rendering data.";
            break;

        default:
            break;
    }
    return gos;
}


template < typename GenericOstream >
GenericOstream & operator<<( GenericOstream &gos, const MFPOLICYMANAGER_ACTION &policyAction )
{
    switch ( policyAction )
    {
        case MFPOLICYMANAGER_ACTION::PEACTION_NO:
            gos << "No action.";
            break;
        case MFPOLICYMANAGER_ACTION::PEACTION_PLAY:
            gos << "Play the stream.";
            break;
        case MFPOLICYMANAGER_ACTION::PEACTION_COPY:
            gos << "Copy the stream.";
            break;
        case MFPOLICYMANAGER_ACTION::PEACTION_EXPORT:
            gos << "Export the stream to another format.";
            break;
        case MFPOLICYMANAGER_ACTION::PEACTION_EXTRACT:
            gos << "Extract the data from the stream and pass it to the application. For example, acoustic echo cancellation requires this action.";
            break;
        case MFPOLICYMANAGER_ACTION::PEACTION_RESERVED1:
            gos << "Reserved.";
            break;
        case MFPOLICYMANAGER_ACTION::PEACTION_RESERVED2:
            gos << "Reserved.";
            break;
        case MFPOLICYMANAGER_ACTION::PEACTION_RESERVED3:
            gos << "Reserved.";
            break;

        default:
            gos << "Unkown Action";
            break;
    }
    return gos;
}


//*****************************************************************************
//  Static Method Declarations
//*****************************************************************************
static IConnector * TraverseParts( IPart *, DataFlow );
static void BeginDeviceTopolgy( IMMDevice * );
static void TraverseTopology( IConnector *, DataFlow );
static void ScanDeviceName( IMMDevice * );
static void ScanDeviceInterfaces( IMMDevice * );
static void ScanPartName( IPart * );
static void ScanPartInterfaces( IPart * );
static void ScanPartControlInterface( IPart * );
static void ScanDefaultAudioEndpoint( EDataFlow, ERole, IMMDeviceEnumerator * );
static void ScanChannelConfiguration( DWORD );
static void ScanPartType_NoTab( DWORD );

//https://msdn.microsoft.com/en-us/library/windows/desktop/dd375432(v=vs.85).aspx
static void _FreeMediaType( AM_MEDIA_TYPE & );
static void _DeleteMediaType( AM_MEDIA_TYPE * );


//*****************************************************************************
//  Global Data
//*****************************************************************************
static bool scanDefaultOnly;
static bool scanActive;
static bool scanDisabled;
static bool scanNotPresent;
static bool scanUnplugged;
static bool displayInterfaces;
static bool displayTopology;
static bool verbose;


//*****************************************************************************
//  Constant variables
//*****************************************************************************
static const char *scanActiveString = "-a";
static const char *scanDisabledString = "-d";
static const char *scanNotPresentString = "-np";
static const char *scanUnpluggedString = "-up";
static const char *scanAllString = "-all";
static const char *scanInterfacesString = "-i";
static const char *scanTopologyString = "-t";
static const char *verboseString= "-v";
static const char *helpStringString = "-h";


//*****************************************************************************
//  Main
//*****************************************************************************
int main( int argc, char ** argv )
{
    MyResult result = S_OK;
    Tabs tabs;

    std::cout << tabs << "Audio Device Scanner" << std::endl;
    tabs.Inc();

    for ( int argIdx = 1; argIdx < argc; argIdx++ )
    {
        const char *arg = argv[argIdx];
        if ( strcmp( arg, scanActiveString ) == 0 )
        {
            scanActive = true;
        }
        else if ( strcmp( arg, scanDisabledString ) == 0 )
        {
            scanDisabled = true;
        }
        else if ( strcmp( arg, scanNotPresentString ) == 0 )
        {
            scanNotPresent = true;
        }
        else if ( strcmp( arg, scanUnpluggedString ) == 0 )
        {
            scanUnplugged = true;
        }
        else if ( strcmp( arg, scanAllString ) == 0 )
        {
            scanActive = true;
            scanDisabled = true;
            scanNotPresent = true;
            scanUnplugged = true;
        }
        else if ( strcmp( arg, scanInterfacesString ) == 0 )
        {
            displayInterfaces = true;
        }
        else if ( strcmp( arg, scanTopologyString ) == 0 )
        {
            displayTopology = true;
        }
        else if ( strcmp( arg, verboseString ) == 0 )
        {
            verbose = true;
        }
        else if ( strcmp( arg, helpStringString ) == 0 )
        {
            std::cout << tabs << "Usage" << std::endl;
            tabs.Inc();

            std::cout << tabs << argv[0] << " <Device State Options> <Scan Options> <Other Options>" << std::endl;
            std::cout << tabs << "where an option is any combination of the following" << std::endl;
            tabs.Inc();

            std::cout << tabs << "Device State Options:" << std::endl;
            tabs.Inc();
            std::cout << tabs << scanActiveString << " (scans all active devices)" << std::endl;
            std::cout << tabs << scanDisabledString << " (scans all disabled devices)" << std::endl;
            std::cout << tabs << scanNotPresentString << " (scans all devices that the system knows about, but are not present)" << std::endl;
            std::cout << tabs << scanUnpluggedString << " (scans all devices the system knows about, but are unplugged)" << std::endl;
            std::cout << tabs << scanAllString << " (scans active, disabled, not present, and unplugged devices)" << std::endl;
            std::cout << std::endl;
            tabs.Dec();


            std::cout << tabs << "In place of "
                << scanActiveString << ", "
                << scanDisabledString << ", "
                << scanNotPresentString << ", or "
                << scanUnpluggedString << ", you can use "
                << scanAllString << ", which indiates to scan all known devices." << std::endl;
            std::cout << tabs << "The program will automatically scan the default capture and render devices if no device states are specified." << std::endl;
            std::cout << std::endl;

            std::cout << tabs << "Scan Options:" << std::endl;
            tabs.Inc();
            std::cout << tabs << scanInterfacesString << " (scans all device and part interfaces)" << std::endl;
            std::cout << tabs << scanTopologyString << " (performs a topological scan on all chosen devices)" << std::endl;
            std::cout << std::endl;
            tabs.Dec();

            std::cout << tabs << "Other Options:" << std::endl;
            tabs.Inc();
            std::cout << tabs << verboseString << " (prints out additional data during scan)" << std::endl;
            std::cout << tabs << helpStringString << " (prints information about program usage, and then exits)" << std::endl;
            std::cout << std::endl;
            tabs.Dec();

            tabs.Dec();

            tabs.Dec();

            return 0;
        }
        else
        {
            std::cout << tabs << "Unkown argument: " << arg << std::endl;
            std::cout << tabs << "To see a list of options, use option \"-h\"" << std::endl;
            return 0;
        }
    }

    if ( !scanActive && !scanDisabled && !scanNotPresent && !scanUnplugged )
    {
        scanDefaultOnly = true;
    }

    std::cout << tabs << "Beginning Device Scan." << std::endl;

    result = CoInitialize( NULL );
    if ( FAILED( result.GetResult() ) )
    {
        std::cout << tabs << "Failed to initialize COM library." << std::endl;
        std::cout << tabs << result << std::endl;
        return -1;
    }
    
    IMMDeviceEnumerator * p_deviceEnumerator = nullptr;
    result = CoCreateInstance( __uuidof( MMDeviceEnumerator ), NULL, CLSCTX_ALL, __uuidof( IMMDeviceEnumerator ), reinterpret_cast< void ** >( & p_deviceEnumerator ) );
    if ( FAILED( result.GetResult() ) )
    {
        std::cout << tabs << "Failed to obtain list of audio devices." << std::endl;
        std::cout << tabs << result << std::endl;

        CoUninitialize();

        return -1;
    }

    tabs.Inc();

    if ( scanDefaultOnly )
    {
        std::cout << tabs << "Scanning default devices" << std::endl;
        tabs.Inc();

        if ( IsWindows7OrGreater() )
        {
            std::cout << tabs << "Communication Caputre Device" << std::endl;
            tabs.Inc();
            ScanDefaultAudioEndpoint( EDataFlow::eCapture, ERole::eCommunications, p_deviceEnumerator );
            tabs.Dec();
            std::cout << std::endl;

            std::cout << tabs << "Console Caputre Device" << std::endl;
            tabs.Inc();
            ScanDefaultAudioEndpoint( EDataFlow::eCapture, ERole::eConsole, p_deviceEnumerator );
            tabs.Dec();
            std::cout << std::endl;

            std::cout << tabs << "Multimedia Caputre Device" << std::endl;
            tabs.Inc();
            ScanDefaultAudioEndpoint( EDataFlow::eCapture, ERole::eMultimedia, p_deviceEnumerator );
            tabs.Dec();
            std::cout << std::endl;

            std::cout << tabs << "Communication Render Device" << std::endl;
            tabs.Inc();
            ScanDefaultAudioEndpoint( EDataFlow::eRender, ERole::eCommunications, p_deviceEnumerator );
            tabs.Dec();
            std::cout << std::endl;

            std::cout << tabs << "Console Render Device" << std::endl;
            tabs.Inc();
            ScanDefaultAudioEndpoint( EDataFlow::eRender, ERole::eConsole, p_deviceEnumerator );
            tabs.Dec();
            std::cout << std::endl;

            std::cout << tabs << "Multimedia Render Device" << std::endl;
            tabs.Inc();
            ScanDefaultAudioEndpoint( EDataFlow::eRender, ERole::eMultimedia, p_deviceEnumerator );
            tabs.Dec();
            std::cout << std::endl;
        }
        else if ( IsWindowsVistaOrGreater() )
        {
            std::cout << tabs << "Default Caputre Device" << std::endl;
            tabs.Inc();
            ScanDefaultAudioEndpoint( EDataFlow::eCapture, ERole::eCommunications, p_deviceEnumerator );
            tabs.Dec();
            std::cout << std::endl;

            std::cout << tabs << "Default Render Device" << std::endl;
            tabs.Inc();
            ScanDefaultAudioEndpoint( EDataFlow::eRender, ERole::eCommunications, p_deviceEnumerator );
            tabs.Dec();
            std::cout << std::endl;
        }

        tabs.Dec();
    }
    else
    {
        if ( scanActive )
        {
            std::cout << tabs << "Scanning all active devices." << std::endl;
        }
        if ( scanDisabled )
        {
            std::cout << tabs << "Scanning all disabled devices." << std::endl;
        }
        if ( scanNotPresent )
        {
            std::cout << tabs << "Scanning all not present devices." << std::endl;
        }
        if ( scanUnplugged )
        {
            std::cout << tabs << "Scanning all unplugged devices." << std::endl;
        }

        tabs.Inc();

        IMMDeviceCollection *p_deviceCollection = nullptr;
        result = p_deviceEnumerator->EnumAudioEndpoints( EDataFlow::eAll, DEVICE_STATE_ACTIVE | DEVICE_STATE_DISABLED | DEVICE_STATE_NOTPRESENT | DEVICE_STATE_UNPLUGGED, &p_deviceCollection );
        if ( SUCCEEDED( result.GetResult() ) )
        {
            UINT deviceCount = 0;
            result = p_deviceCollection->GetCount( &deviceCount );
            if ( SUCCEEDED( result.GetResult() ) )
            {
                std::cout << tabs << "Discovered " << deviceCount << " devices." << std::endl;
                tabs.Inc();
                for ( UINT deviceIdx = 0; deviceIdx < deviceCount; ++deviceIdx )
                {
                    IMMDevice *p_device = nullptr;
                    result = p_deviceCollection->Item( deviceIdx, &p_device );
                    if ( SUCCEEDED( result.GetResult() ) )
                    {
                        DWORD deviceState = 0;
                        result = p_device->GetState( &deviceState );
                        if ( FAILED( result.GetResult() ) )
                        {
                            std::cout << tabs << "Failed to get current device state. Skipping Device." << std::endl;
                            std::cout << tabs << result << std::endl;
                            continue;
                        }

                        if ( (deviceState & DEVICE_STATE_ACTIVE) && (scanActive == false) )
                        {
                            continue;
                        }
                        if ( (deviceState & DEVICE_STATE_DISABLED) && (scanDisabled == false) )
                        {
                            continue;
                        }
                        if ( (deviceState & DEVICE_STATE_NOTPRESENT) && (scanNotPresent == false) )
                        {
                            continue;
                        }
                        if ( (deviceState & DEVICE_STATE_UNPLUGGED) && (scanUnplugged == false) )
                        {
                            continue;
                        }

                        std::cout << tabs << "Device " << deviceIdx + 1 << std::endl;

                        ScanDeviceName( p_device );

                        tabs.Inc();
                        if ( displayInterfaces )
                        {
                            std::cout << tabs << "Scanning Device Interfaces" << std::endl << std::endl;
                            ScanDeviceInterfaces( p_device );
                        }

                        if ( displayTopology )
                        {
                            std::cout << tabs << "Traversing Device Topology" << std::endl << std::endl;
                            BeginDeviceTopolgy( p_device );
                        }

                        tabs.Dec();
                        p_device->Release();
                        std::cout << std::endl;
                    }
                    else
                    {
                        std::cout << tabs << "Failed to get device " << deviceIdx + 1 << ". Skipping." << std::endl;
                        std::cout << tabs << result << std::endl;
                    }
                }

                tabs.Dec();
            }
            else
            {
                std::cout << "Failed to obtain audio device count." << std::endl;
                std::cout << tabs << result << std::endl;
            }

            p_deviceCollection->Release();
        }
        else
        {
            std::cout << tabs << "Failed to obtain audio devices." << std::endl;
            std::cout << tabs << result << std::endl;
        }

        tabs.Dec();
    }

    tabs.Dec();

    p_deviceEnumerator->Release();

    CoUninitialize();

    std::cout << tabs << "Device scan finished." << std::endl;

    return 0;
}


//*****************************************************************************
//  Method Bodies
//*****************************************************************************
static IConnector * TraverseParts( IPart *p_currentPart, DataFlow direction )
{
    MyResult result = S_OK;
    Tabs tabs;
    IConnector *p_nextConnector = nullptr;

    if ( !p_currentPart )
    {
        return nullptr;
    }

    ScanPartName( p_currentPart );
    ScanPartInterfaces( p_currentPart );
    ScanPartControlInterface( p_currentPart );

    IPartsList *p_partsList = nullptr;
    switch ( direction )
    {
        case DataFlow::In:
            result = p_currentPart->EnumPartsIncoming( &p_partsList );
            break;

        case DataFlow::Out:
            result = p_currentPart->EnumPartsOutgoing( &p_partsList );
            break;

        default:
            return nullptr;
    }

    if ( SUCCEEDED( result.GetResult() ) )
    {
        IPart *p_nextPart = nullptr;
        result = p_partsList->GetPart( 0, &p_nextPart );
        if ( SUCCEEDED( result.GetResult() ) )
        {
            PartType partType = PartType::Connector;
            result = p_nextPart->GetPartType( &partType );
            if ( SUCCEEDED( result.GetResult() ) )
            {
                std::cout << std::endl;
                std::cout << tabs << "Encountered Next Part" << std::endl;
                if ( partType == PartType::Connector )
                {
                    result = p_nextPart->QueryInterface( __uuidof( IConnector ), reinterpret_cast< void ** >( &p_nextConnector ) );
                    if ( SUCCEEDED( result.GetResult() ) )
                    {
                        ConnectorType connectionType = ConnectorType::Unknown_Connector;
                        result = p_nextConnector->GetType( &connectionType );
                        if ( SUCCEEDED( result.GetResult() ) )
                        {
                            std::cout << tabs << "Connection: " << connectionType << std::endl;

                            ScanPartName( p_nextPart );
                            ScanPartInterfaces( p_nextPart );
                            ScanPartControlInterface( p_nextPart );
                        }
                        else
                        {
                            std::cout << tabs << "Failed to obtain the connection part." << std::endl;
                            std::cout << tabs << result << std::endl;
                        }
                    }
                    else
                    {
                        std::cout << tabs << "Failed to obtain the type of the next part." << std::endl;
                        std::cout << tabs << result << std::endl;
                    }
                }
                else if ( partType == PartType::Subunit )
                {
                    p_nextConnector = TraverseParts( p_nextPart, direction );
                }
                else
                {
                    std::cout << tabs << "Encountered part of unknown type. Ending topology scan." << std::endl;
                    return nullptr;
                }
            }
            else
            {
                std::cout << tabs << "Failed to obtain the type of the next part." << std::endl;
                std::cout << tabs << result << std::endl;
            }

            p_nextPart->Release();
        }
        else
        {
            std::cout << tabs << "Failed to obtain a next part in the topology." << std::endl;
            std::cout << tabs << result << std::endl;
        }
    }
    else
    {
        std::cout << tabs << "Failed to obtain a part list from the topology." << std::endl;
        std::cout << tabs << result << std::endl;
    }

    return p_nextConnector;
}


static void BeginDeviceTopolgy( IMMDevice *p_device )
{
    MyResult result S_OK;
    Tabs tabs;

    IDeviceTopology *p_deviceTopology = nullptr;
    result = p_device->Activate( __uuidof( IDeviceTopology ), CLSCTX_ALL, NULL, reinterpret_cast< void ** >( &p_deviceTopology ) );
    if ( SUCCEEDED( result.GetResult() ) )
    {
        tabs.Inc();

        UINT connectorCount = 0;
        result = p_deviceTopology->GetConnectorCount( &connectorCount );
        if ( SUCCEEDED( result.GetResult() ) )
        {
            std::cout << tabs << "Device has " << connectorCount << " connectors." << std::endl;
            tabs.Inc();

            for ( UINT connectorIdx = 0; connectorIdx < connectorCount; connectorIdx++ )
            {
                std::cout << tabs << "Connection " << connectorIdx + 1 << std::endl;
                tabs.Inc();

                IConnector *p_connector = nullptr;
                result = p_deviceTopology->GetConnector( connectorIdx, &p_connector );
                if ( SUCCEEDED( result.GetResult() ) )
                {
                    DataFlow dataFlow = DataFlow::In;
                    result = p_connector->GetDataFlow( &dataFlow );
                    if ( SUCCEEDED( result.GetResult() ) )
                    {
                        std::cout << tabs << "Connection Direction: " << dataFlow << std::endl;
                        TraverseTopology( p_connector, dataFlow );
                    }
                    else
                    {
                        std::cout << tabs << "Failed to get connection direction." << std::endl;
                        std::cout << tabs << result << std::endl;
                    }
                }
                else
                {
                    std::cout << tabs << "Failed to get device connection." << std::endl;
                    std::cout << tabs << result << std::endl;
                }

                tabs.Dec();
                p_connector->Release();
            }

            tabs.Dec();
        }
        else
        {
            std::cout << tabs << "Failed to get device count." << std::endl;
            std::cout << tabs << result << std::endl;
        }

        tabs.Dec();
    }
    else if ( result == E_NOTFOUND )
    {
        std::cout << tabs << "Device Toplogy is not supported by this device." << std::endl;
    }
    else
    {
        std::cout << tabs << "Failed to obtain the device topology's starting point." << std::endl;
        std::cout << tabs << result << std::endl;
    }
}


static void TraverseTopology( IConnector *from, DataFlow direction )
{
    MyResult result = S_OK;
    BOOL connected = FALSE;
    Tabs tabs;

    result = from->IsConnected( &connected );
    if (  SUCCEEDED( result.GetResult() ) )
    {
        if ( connected )
        {
            IConnector *p_connectionTo = nullptr;
            result = from->GetConnectedTo( &p_connectionTo );
            if ( SUCCEEDED( result.GetResult() ) )
            {
                IPart *p_nextPart = nullptr;
                result = p_connectionTo->QueryInterface( __uuidof( IPart ), reinterpret_cast< void ** >( &p_nextPart ) );
                if ( SUCCEEDED( result.GetResult() ) )
                {
                    std::cout << tabs << "Connection Start." << std::endl;

                    IConnector *p_nextConnector = nullptr;
                    tabs.Inc();

                    p_nextConnector = TraverseParts( p_nextPart, direction );
                    tabs.Dec();

                    if ( p_nextConnector )
                    {
                        std::cout << tabs << "Connection End." << std::endl << std::endl;
                        TraverseTopology( p_nextConnector, direction );
                        p_nextConnector->Release();
                    }
                    else
                    {
                        std::cout << tabs << "Topology end unexpectedly reached." << std::endl;
                    }

                    p_nextPart->Release();
                }
                else
                {
                    std::cout << tabs << "Failed to obtain next part in topologyy." << std::endl;
                    std::cout << tabs << result << std::endl;
                }

                p_connectionTo->Release();
            }
            else
            {
                std::cout << tabs << "Failed to obtain connection." << std::endl;
                std::cout << tabs << result << std::endl;
            }
        }
    }
    else
    {
        std::cout << tabs << "Failed to determine if subsequent part was connected." << std::endl;
        std::cout << tabs << result << std::endl;
    }
}


static void ScanDeviceName( IMMDevice *p_device )
{
    MyResult result = S_OK;
    Tabs tabs;

    tabs.Inc();

    IPropertyStore *p_propertyStore = nullptr;
    std::cout << tabs << "Name: ";
    result = p_device->OpenPropertyStore( STGM_READ, &p_propertyStore );
    if ( SUCCEEDED( result.GetResult() ) )
    {
        PROPVARIANT propertyVariant;
        PropVariantInit( &propertyVariant );
        result = p_propertyStore->GetValue( PKEY_Device_FriendlyName, &propertyVariant );
        if ( SUCCEEDED( result.GetResult() ) )
        {
            std::cout << propertyVariant.pwszVal << std::endl;
        }
        else
        {
            std::cout << "Unknown Device Name." << std::endl;
            std::cout << tabs << result << std::endl;
        }
        p_propertyStore->Release();
    }
    else
    {
        std::cout << "Unable to retrieve device name." << std::endl;
        std::cout << tabs << result << std::endl;
    }

    DWORD deviceState = 0;
    result = p_device->GetState( &deviceState );
    std::cout << tabs << "Status: ";
    if ( SUCCEEDED( result.GetResult() ) )
    {
        if ( deviceState & DEVICE_STATE_ACTIVE )
        {
            std::cout << "Active." << std::endl;
        }
        if ( deviceState & DEVICE_STATE_DISABLED )
        {
            std::cout << "Disabled." << std::endl;
        }
        if ( deviceState & DEVICE_STATE_NOTPRESENT )
        {
            std::cout << "Not Present." << std::endl;
        }
        if ( deviceState & DEVICE_STATE_UNPLUGGED )
        {
            std::cout << "Unplugged." << std::endl;
        }
    }
    else
    {
        std::cout << "Unable to retrieve device status." << std::endl;
        std::cout << tabs << result << std::endl;
    }

    if ( verbose )
    {
        LPWSTR deviceId;
        result = p_device->GetId( &deviceId );
        if ( SUCCEEDED( result.GetResult() ) )
        {
            std::cout << tabs << "ID: ";
            if ( deviceId && *deviceId )
            {
                std::cout << deviceId << std::endl;
            }
            else
            {
                std::cout << "Unknown" << std::endl;
            }
            CoTaskMemFree( deviceId );
        }
        else
        {
            std::cout << tabs << "Unable to obtain device ID.";
            std::cout << tabs << result << std::endl;
        }
    }
}


static void ScanDeviceInterfaces( IMMDevice *p_device )
{
    MyResult result = S_OK;
    Tabs tabs;

    tabs.Inc();

    bool hasInterface = false;

    IPropertyStore *p_propertyStore = nullptr;
    result = p_device->OpenPropertyStore( STGM_READ, &p_propertyStore );
    if ( SUCCEEDED( result.GetResult() ) )
    {
        hasInterface = true;
        std::cout << tabs << "Property Store Interface" << std::endl;

        if ( verbose )
        {
            tabs.Inc();

            PROPVARIANT propertyVariant;
            PropVariantInit( &propertyVariant );

            result = p_propertyStore->GetValue( PKEY_DeviceInterface_FriendlyName, &propertyVariant );
            if ( SUCCEEDED( result.GetResult() ) )
            {
                std::cout << tabs << "Adapter Name: " << propertyVariant.pwszVal << std::endl;
            }

            result = p_propertyStore->GetValue( PKEY_Device_DeviceDesc, &propertyVariant );
            if ( SUCCEEDED( result.GetResult() ) )
            {
                std::cout << tabs << "Device Description: " << propertyVariant.pwszVal << std::endl;
            }

            DWORD propertyCount = 0;
            result = p_propertyStore->GetCount( &propertyCount );
            if ( SUCCEEDED( result.GetResult() ) )
            {
                std::cout << tabs << "Discovered " << propertyCount << " properties." << std::endl;
                tabs.Inc();

                for ( DWORD propertyIdx = 0; propertyIdx < propertyCount; propertyIdx++ )
                {
                    std::cout << tabs << "Property " << propertyIdx + 1 << std::endl;
                    tabs.Inc();

                    PROPERTYKEY propertyKey;
                    result = p_propertyStore->GetAt( propertyIdx, &propertyKey );
                    if ( SUCCEEDED( result.GetResult() ) )
                    {
                        result = p_propertyStore->GetValue( propertyKey, &propertyVariant );
                        if ( SUCCEEDED( result.GetResult( ) ) )
                        {
                            BOOL converted;
                            SYSTEMTIME  systemTime;

                            std::cout << tabs << "Property Key: " << propertyKey << std::endl;
                            std::cout << tabs << "Property Value: ";

                            if ( propertyVariant.vt == VT_EMPTY )
                            {
                                std::cout << "empty property" << std::endl;
                                continue;
                            }

                            if ( propertyVariant.vt & VT_VECTOR )
                            {
                                std::cout << "A vector of ";
                                ScanPartType_NoTab( propertyVariant.vt );
                                std::cout << std::endl;
                                continue;
                            }

                            if ( propertyVariant.vt & VT_ARRAY )
                            {

                                std::cout << "An array of ";
                                ScanPartType_NoTab( propertyVariant.vt );
                                std::cout << std::endl;
                                continue;
                            }

                            if ( propertyVariant.vt & VT_BYREF )
                            {
                                std::cout << "A reference to .";
                                ScanPartType_NoTab( propertyVariant.vt );
                                std::cout << std::endl;
                                continue;
                            }

                            // https://msdn.microsoft.com/en-us/library/windows/desktop/aa380072(v=vs.85).aspx
                            switch ( propertyVariant.vt )
                            {
                                case VT_NULL:
                                    std::cout << "NULL";
                                    break;

                                case VT_I2:
                                    std::cout << propertyVariant.iVal;
                                    break;

                                case VT_I4:
                                    std::cout << propertyVariant.lVal;
                                    break;

                                case VT_R4:
                                    std::cout << propertyVariant.fltVal;
                                    break;

                                case VT_R8:
                                    std::cout << propertyVariant.dblVal;
                                    break;

                                case VT_CY:
                                    std::cout << propertyVariant.cyVal.int64 
                                        << ", high - " << propertyVariant.cyVal.Hi
                                        << ", low - " << propertyVariant.cyVal.Lo
                                        << ".";
                                    break;

                                case VT_DATE:
                                    std::cout << propertyVariant.date;
                                    break;

                                case VT_BSTR:
                                    std::cout << propertyVariant.bstrVal;
                                    break;

                                case VT_DISPATCH:
                                    std::cout << propertyVariant.pdispVal;
                                    break;

                                case VT_ERROR:
                                    std::cout << propertyVariant.scode;
                                    break;

                                case VT_BOOL:
                                    std::cout << (!propertyVariant.boolVal ? "TRUE" : "FALSE");
                                    break;

                                case VT_VARIANT:
                                    std::cout << "List of prop propertyVariants, containing " << propertyVariant.capropvar.cElems << " elements.";
                                    break;

                                case VT_UNKNOWN:
                                    std::cout << "IUnknown data." ;
                                    break;

                                case VT_DECIMAL:
                                    std::cout << "Decimal Value.";
                                    break;

                                case VT_I1:
                                    std::cout << propertyVariant.cVal;
                                    break;

                                case VT_UI1:
                                    std::cout << propertyVariant.bVal;
                                    break;

                                case VT_UI2:
                                    std::cout << propertyVariant.uiVal;
                                    break;

                                case VT_UI4:
                                    std::cout << propertyVariant.ulVal;
                                    break;

                                case VT_I8:
                                    std::cout << propertyVariant.hVal.QuadPart
                                        << ", high - " << propertyVariant.hVal.HighPart
                                        << ", low - " << propertyVariant.hVal.LowPart
                                        << ".";
                                    break;

                                case VT_UI8:
                                    std::cout << propertyVariant.uhVal.QuadPart
                                        << ", high - " << propertyVariant.uhVal.HighPart
                                        << ", low - " << propertyVariant.uhVal.LowPart
                                        << ".";
                                    break;

                                case VT_INT:
                                    std::cout << propertyVariant.intVal;
                                    break;

                                case VT_UINT:
                                    std::cout << propertyVariant.uintVal;
                                    break;

                                case VT_LPSTR:
                                    std::cout << propertyVariant.pszVal;
                                    break;

                                case VT_LPWSTR:
                                    std::cout << propertyVariant.pwszVal;
                                    break;

                                case VT_FILETIME:
                                    converted = FileTimeToSystemTime( &propertyVariant.filetime, &systemTime );
                                    if ( converted )
                                    {
                                        std::cout << systemTime;
                                    }
                                    else
                                    {
                                        std::cout << "Unable to convert the given time value";
                                    }
                                    break;

                                case VT_BLOB:
                                    std::cout << "Blob data of " << propertyVariant.blob.cbSize << " bytes.";
                                    break;

                                case VT_STREAM:
                                    std::cout << "IStream data at address 0x"
                                        << std::hex
                                        << std::uppercase
                                        << propertyVariant.pStream
                                        << std::dec;
                                    break;

                                case VT_STORAGE:
                                    std::cout << "IStorage data at address 0x"
                                        << std::hex
                                        << std::uppercase
                                        << propertyVariant.pStorage
                                        << std::dec;
                                    break;

                                case VT_STREAMED_OBJECT:
                                    std::cout << "IStream data, with serialized object at address 0x"
                                        << std::hex
                                        << std::uppercase
                                        << propertyVariant.pStream
                                        << std::dec;
                                    break;

                                case VT_STORED_OBJECT:
                                    std::cout << "IStorage data with loadable object at address 0x"
                                        << std::hex
                                        << std::uppercase
                                        << propertyVariant.pStorage
                                        << std::dec;
                                    break;

                                case VT_BLOB_OBJECT:
                                    std::cout << "Serialized blob object, similar to IStream object, of " << propertyVariant.blob.cbSize << " bytes.";
                                    break;

                                case VT_CF:
                                    if ( propertyVariant.pclipdata )
                                    {
                                        std::cout << "Clip data containing " 
                                            << propertyVariant.pclipdata->cbSize 
                                            << " bytes of format " 
                                            << propertyVariant.pclipdata->ulClipFmt 
                                            << ".";
                                    }
                                    else
                                    {
                                        std::cout << "Null clip data.";
                                    }
                                    break;

                                case VT_CLSID:
                                    std::cout << *propertyVariant.puuid;
                                    break;

                                case VT_VERSIONED_STREAM:
                                    std::cout << "IStream with guid " << propertyVariant.pVersionedStream->guidVersion << ".";
                                    break;

                                case VT_RESERVED:
                                    std::cout << "Reserved space. You shouldn't ever see this. Conglaturations.";
                                    break;

                                case 0xfff: // VT_BSTR_BLOB, VT_ILLEGAL, VT_ILLEGALMASKED, and VT_TYPEMASK
                                    std::cout << "For system use only, potentially VT_BSTR_BLOB, VT_ILLEGAL, VT_ILLEGALMASKED, or VT_TYPEMASK.";
                                    break;

                                default:
                                    std::cout << "Unkown propertyVariant result for key " << propertyKey << ".";
                                    break;
                            }

                            std::cout << std::endl;
                        }
                        else
                        {
                            std::cout << tabs << "Failed ot obtain the property value from the current key." << std::endl;
                            std::cout << tabs << result << std::endl;
                        }
                    }
                    else
                    {
                        std::cout << tabs << "Failed ot obtain the property key." << std::endl;
                        std::cout << tabs << result << std::endl;
                    }

                    tabs.Dec();
                    PropVariantClear( &propertyVariant );
                }

                tabs.Dec();
            }
            else
            {
                std::cout << tabs << "Failed ot obtain a count of current properties." << std::endl;
                std::cout << tabs << result << std::endl;
            }

            tabs.Dec();
        }

        p_propertyStore->Release();
    }
    else if ( result != E_NOINTERFACE )
    {
        std::cout << tabs << "Failed to scan Property Store Interface." << std::endl;
        std::cout << tabs << result << std::endl;
    }

    IAudioClient *p_audioClient = nullptr;
    result = p_device->Activate( __uuidof( IAudioClient ), CLSCTX_ALL, NULL, reinterpret_cast< void ** >( &p_audioClient ) );
    if ( SUCCEEDED( result.GetResult() ) )
    {
        hasInterface = true;
        std::cout << tabs << "Audio Client Interface" << std::endl;

        if ( verbose )
        {
            tabs.Inc();

            WAVEFORMATEXTENSIBLE *p_audioClientFormat;
            result = p_audioClient->GetMixFormat( reinterpret_cast< WAVEFORMATEX **>( &p_audioClientFormat ) );
            if ( SUCCEEDED( result.GetResult() ) )
            {
                std::cout << tabs << "Audio Client Preferred Format" << std::endl;
                tabs.Inc();

                std::cout << tabs << "Sub Format: " << p_audioClientFormat->SubFormat << std::endl;
                std::cout << tabs << "Channel Mask: " << p_audioClientFormat->dwChannelMask << std::endl;

                ScanChannelConfiguration( p_audioClientFormat->dwChannelMask );

                std::cout << tabs << "Samples - Samples Per Block: " << p_audioClientFormat->Samples.wSamplesPerBlock << std::endl;
                std::cout << tabs << "Samples - Valid Bits Per Sample: " << p_audioClientFormat->Samples.wValidBitsPerSample << std::endl;
                std::cout << tabs << "Samples - Reserved: " << p_audioClientFormat->Samples.wReserved << std::endl;

                std::cout << tabs << "Format - Format Tag: " << p_audioClientFormat->Format.wFormatTag << std::endl;
                std::cout << tabs << "Format - Average Bytes Per Second: " << p_audioClientFormat->Format.nAvgBytesPerSec << std::endl;
                std::cout << tabs << "Format - Block Align: " << p_audioClientFormat->Format.nBlockAlign << std::endl;
                std::cout << tabs << "Format - Channels: " << p_audioClientFormat->Format.nChannels << std::endl;
                std::cout << tabs << "Format - Samples Per Second: " << p_audioClientFormat->Format.nSamplesPerSec << std::endl;
                std::cout << tabs << "Format - Bits Per Sample: " << p_audioClientFormat->Format.wBitsPerSample << std::endl;
                std::cout << tabs << "Format - Format Struct Size: " << p_audioClientFormat->Format.cbSize << std::endl;

                tabs.Dec();
                CoTaskMemFree( p_audioClientFormat );
            }
            else
            {
                std::cout << tabs << "Failed to obtain audio render preferred format." << std::endl;
                std::cout << tabs << result << std::endl;
            }

            REFERENCE_TIME defaultPeriod;
            REFERENCE_TIME minimumPeriod;
            result = p_audioClient->GetDevicePeriod( &defaultPeriod, &minimumPeriod );
            if ( SUCCEEDED( result.GetResult() ) )
            {
                std::cout << tabs << "Audio Client Default Period: " << defaultPeriod << std::endl;
                std::cout << tabs << "Audio Client Minimum Period: " << minimumPeriod << std::endl;
            }
            else
            {
                std::cout << tabs << "Failed to obtain audio render device period." << std::endl;
                std::cout << tabs << result << std::endl;
            }

            tabs.Dec();
        }

        p_audioClient->Release();
    }
    else if ( result != E_NOINTERFACE )
    {
        std::cout << tabs << "Failed to scan Audio Client Interfacee." << std::endl;
        std::cout << tabs << result << std::endl;
    }

    IAudioEndpointVolume *p_audioEndpointVolume = nullptr;
    result = p_device->Activate( __uuidof( IAudioEndpointVolume ), CLSCTX_ALL, NULL, reinterpret_cast< void ** >( &p_audioEndpointVolume ) );
    if ( SUCCEEDED( result.GetResult() ) )
    {
        hasInterface = true;
        std::cout << tabs << "Audio Endpoint Volume Control Interface" << std::endl;

        if ( verbose )
        {
            tabs.Inc();

            UINT channelCount = 0;
            result = p_audioEndpointVolume->GetChannelCount( &channelCount );
            if ( SUCCEEDED( result.GetResult() ) )
            {
                if ( channelCount > 0 )
                {
                    std::cout << tabs << "Channel Data" << std::endl;
                }
                else
                {
                    std::cout << tabs << "No individual channels detected" << std::endl;
                }

                tabs.Inc();

                for ( UINT channelIdx = 0; channelIdx < channelCount; channelIdx++ )
                {
                    std::cout << tabs << "Channel " << channelIdx + 1 << std::endl;
                    tabs.Inc();

                    float volumedB = 0.0f;
                    result = p_audioEndpointVolume->GetChannelVolumeLevel( channelIdx, &volumedB );
                    if ( SUCCEEDED( result.GetResult() ) )
                    {
                        std::cout << tabs << "Channel Volume: " << volumedB << " dB" << std::endl;
                    }
                    else
                    {
                        std::cout << tabs << "Failed to obtain channel volume level." << std::endl;
                        std::cout << tabs << result << std::endl;
                    }

                    float volumeScaler = 0.0f;
                    result = p_audioEndpointVolume->GetChannelVolumeLevelScalar( channelIdx, &volumeScaler );
                    if ( SUCCEEDED( result.GetResult() ) )
                    {
                        std::cout << tabs << "Channel Volume Scaler: " << volumeScaler << std::endl;
                    }
                    else
                    {
                        std::cout << tabs << "Failed to obtain channel volume scaler." << std::endl;
                        std::cout << tabs << result << std::endl;
                    }

                    tabs.Dec();
                }

                tabs.Dec();

                float masterVolumedB = 0.0f;
                result = p_audioEndpointVolume->GetMasterVolumeLevel( &masterVolumedB );
                if ( SUCCEEDED( result.GetResult() ) )
                {
                    std::cout << tabs << "Master Volume: " << masterVolumedB << " dB" << std::endl;
                }
                else
                {
                    std::cout << tabs << "Failed to obtain master volume." << std::endl;
                    std::cout << tabs << result << std::endl;
                }

                float masterVolumeScaler = 0.0f;
                result = p_audioEndpointVolume->GetMasterVolumeLevelScalar( &masterVolumeScaler );
                if ( SUCCEEDED( result.GetResult() ) )
                {
                    std::cout << tabs << "Master Volume Scaler: " << masterVolumeScaler << std::endl;
                }
                else
                {
                    std::cout << tabs << "Failed to obtain master volume scaler." << std::endl;
                    std::cout << tabs << result << std::endl;
                }

                BOOL muted = FALSE;
                result =  p_audioEndpointVolume->GetMute( &muted );
                if ( SUCCEEDED( result.GetResult() ) )
                {
                    std::cout << tabs << ( muted == TRUE ? "Muted" : "Unmuted" ) << std::endl;
                }
                else
                {
                    std::cout << tabs << "Failed to obtain master volume settings." << std::endl;
                    std::cout << tabs << result << std::endl;
                }
            }
            else
            {
                std::cout << tabs << "Failed to obtain channel count." << std::endl;
                std::cout << tabs << result << std::endl;
            }

            float minVolumedB = 0.0f;
            float maxVolumedB = 0.0f;
            float volumeIncrementdB = 0.0f;
            result = p_audioEndpointVolume->GetVolumeRange( &minVolumedB, &maxVolumedB, &volumeIncrementdB );
            if ( SUCCEEDED( result.GetResult() ) )
            {
                std::cout << tabs << "Volume Ranges" << std::endl;
                tabs.Inc();
                std::cout << tabs << "Min Volume: " << minVolumedB << " dB" << std::endl;
                std::cout << tabs << "Max Volume: " << maxVolumedB << " dB" << std::endl;
                std::cout << tabs << "Volume Increment: " << volumeIncrementdB<< " dB" << std::endl;
                tabs.Dec();
            }
            else
            {
                std::cout << tabs << "Failed to obtain endpoint audio volume." << std::endl;
                std::cout << tabs << result << std::endl;
            }

            UINT currentVolumeStep = 0;
            UINT volumeSteps = 0;
            result = p_audioEndpointVolume->GetVolumeStepInfo( &currentVolumeStep, &volumeSteps );
            if ( SUCCEEDED( result.GetResult() ) )
            {
                std::cout << tabs << "Volume Slider Step Info" << std::endl;
                tabs.Inc();
                std::cout << tabs << "Number of Steps: " << volumeSteps << std::endl;
                std::cout << tabs << "Current Step: " << currentVolumeStep << std::endl;
                tabs.Dec();
            }
            else
            {
                std::cout << tabs << "Failed to obtain volume step info." << std::endl;
                std::cout << tabs << result << std::endl;
            }

            DWORD volumeHardwareSupportMask = 0;
            result = p_audioEndpointVolume->QueryHardwareSupport( &volumeHardwareSupportMask );
            if ( SUCCEEDED( result.GetResult() ) )
            {
                std::cout << tabs << "Supported Hardware" << std::endl;
                tabs.Inc();
                if ( volumeHardwareSupportMask )
                {
                    if ( volumeHardwareSupportMask & ENDPOINT_HARDWARE_SUPPORT_VOLUME )
                    {
                        std::cout << tabs << "Volume control" << std::endl;
                    }
                    if ( volumeHardwareSupportMask & ENDPOINT_HARDWARE_SUPPORT_MUTE )
                    {
                        std::cout << tabs << "Mute control" << std::endl;
                    }
                    if ( volumeHardwareSupportMask & ENDPOINT_HARDWARE_SUPPORT_METER )
                    {
                        std::cout << tabs << "Peak meter" << std::endl;
                    }
                }
                else
                {
                    std::cout << tabs << "No supported hardware" << std::endl;
                }
                tabs.Dec();
            }
            else
            {
                std::cout << tabs << "Failed to obtain supported hardware data." << std::endl;
                std::cout << tabs << result << std::endl;
            }

            tabs.Dec();
        }

        p_audioEndpointVolume->Release();
    }
    else if ( result != E_NOINTERFACE )
    {
        std::cout << tabs << "Failed to scan Audio Endpoint Volume Control Interface." << std::endl;
        std::cout << tabs << result << std::endl;
    }

    IAudioMeterInformation *p_audioMeterInformation = nullptr;
    result = p_device->Activate( __uuidof( IAudioMeterInformation ), CLSCTX_ALL, NULL, reinterpret_cast< void ** >( &p_audioMeterInformation ) );
    if ( SUCCEEDED( result.GetResult() ) )
    {
        hasInterface = true;
        std::cout << tabs << "Audio Meter Information Interface" << std::endl;

        if ( verbose )
        {
            tabs.Inc();

            UINT channelCount = 0;
            result = p_audioMeterInformation->GetMeteringChannelCount( &channelCount );
            if ( SUCCEEDED( result.GetResult() ) )
            {
                std::cout << tabs << "Contians " << channelCount << " Channels" << std::endl;
                tabs.Inc();

                float *channelPeaks = new float[channelCount];
                result = p_audioMeterInformation->GetChannelsPeakValues( channelCount, channelPeaks );
                if ( SUCCEEDED( result.GetResult() ) )
                {
                    for ( UINT channelIdx = 0; channelIdx < channelCount; channelIdx++ )
                    {
                        std::cout << tabs << "Channel " << channelIdx + 1 << " Peak: " << channelPeaks[channelIdx] << std::endl;
                    }
                }
                else
                {
                    std::cout << tabs << "Failed to obtain channel peaks." << std::endl;
                    std::cout << tabs << result << std::endl;
                }

                tabs.Dec();
                delete [] channelPeaks;
            }
            else
            {
                std::cout << tabs << "Failed to obtain channel count." << std::endl;
                std::cout << tabs << result << std::endl;
            }

            float meterPeak = 0.0f;
            result = p_audioMeterInformation->GetPeakValue( &meterPeak );
            if ( SUCCEEDED( result.GetResult() ) )
            {
                std::cout << tabs << "Peak Value: " << meterPeak << std::endl;
            }
            else
            {
                std::cout << tabs << "Failed to obtain peak value." << std::endl;
                std::cout << tabs << result << std::endl;
            }

            DWORD hardwareSupportMask = 0;
            result = p_audioMeterInformation->QueryHardwareSupport( &hardwareSupportMask );
            if ( SUCCEEDED( result.GetResult() ) )
            {
                std::cout << tabs << "Supported Hardware" << std::endl;
                tabs.Inc();

                if ( hardwareSupportMask )
                {
                    if ( hardwareSupportMask & ENDPOINT_HARDWARE_SUPPORT_VOLUME )
                    {
                        std::cout << tabs << "Volume control" << std::endl;
                    }
                    if ( hardwareSupportMask & ENDPOINT_HARDWARE_SUPPORT_MUTE )
                    {
                        std::cout << tabs << "Mute control" << std::endl;
                    }
                    if ( hardwareSupportMask & ENDPOINT_HARDWARE_SUPPORT_METER )
                    {
                        std::cout << tabs << "Peak meter" << std::endl;
                    }
                }
                else
                {
                    std::cout << tabs << "No supported hardware" << std::endl;
                }

                tabs.Dec();
            }
            else
            {
                std::cout << tabs << "Failed to obtain hardware support information." << std::endl;
                std::cout << tabs << result << std::endl;
            }

            tabs.Dec();
        }

        p_audioMeterInformation->Release();
    }
    else if ( result != E_NOINTERFACE )
    {
        std::cout << tabs << "Failed to scan Audio Meter Information Interface." << std::endl;
        std::cout << tabs << result << std::endl;
    }

    IAudioSessionManager *p_audioSessionManager = nullptr;
    result = p_device->Activate( __uuidof( IAudioSessionManager ), CLSCTX_ALL, NULL, reinterpret_cast< void ** >( &p_audioSessionManager ) );
    if ( SUCCEEDED( result.GetResult() ) )
    {
        hasInterface = true;
        std::cout << tabs << "Audio Session Manager Interface" << std::endl;
        p_audioSessionManager->Release();
    }
    else if ( result != E_NOINTERFACE )
    {
        std::cout << tabs << "Failed to scan Session Manager Interfacee." << std::endl;
        std::cout << tabs << result << std::endl;
    }

    IAudioSessionManager2 *p_audioSessionManager2  = nullptr;
    result = p_device->Activate( __uuidof( IAudioSessionManager2 ), CLSCTX_ALL, NULL, reinterpret_cast< void ** >( &p_audioSessionManager2 ) );
    if ( SUCCEEDED( result.GetResult() ) )
    {
        hasInterface = true;
        std::cout << tabs << "Audio Session Manager 2 Interface" << std::endl;

        if ( verbose )
        {
            tabs.Inc();

            IAudioSessionEnumerator *sessionEnumerator;
            result = p_audioSessionManager2->GetSessionEnumerator( &sessionEnumerator );
            if ( SUCCEEDED( result.GetResult() ) )
            {
                int audioCountSession = 0;
                result = sessionEnumerator->GetCount( &audioCountSession );
                if ( SUCCEEDED( result.GetResult() ) )
                {
                    std::cout << tabs << "Detected " << audioCountSession << " sessions." << std::endl;
                    tabs.Inc();

                    for ( int sessionIdx = 0; sessionIdx < audioCountSession; sessionIdx++ )
                    {
                        std::cout << tabs << "Session " << sessionIdx + 1 << std::endl;
                        tabs.Inc();

                        IAudioSessionControl *p_audioControlSession;
                        result = sessionEnumerator->GetSession( sessionIdx, &p_audioControlSession );
                        if ( SUCCEEDED( result.GetResult() ) )
                        {
                            LPWSTR displayName;
                            result = p_audioControlSession->GetDisplayName( &displayName );
                            if ( SUCCEEDED( result.GetResult() ) )
                            {
                                std::cout << tabs << "Session Display Name: ";
                                if ( displayName && *displayName )
                                {
                                    std::cout << displayName << std::endl;
                                }
                                else
                                {
                                    std::cout << "Unknown" << std::endl;
                                }
                                CoTaskMemFree( displayName );
                            }
                            else
                            {
                                std::cout << tabs << "Failed to obtain session display name." << std::endl;
                                std::cout << tabs << result << std::endl;
                            }

                            GUID groupingParam;
                            result = p_audioControlSession->GetGroupingParam( &groupingParam );
                            if ( SUCCEEDED( result.GetResult() ) )
                            {
                                std::cout << tabs << "Grouping Parameter: " << groupingParam << std::endl;
                            }
                            else
                            {
                                std::cout << tabs << "Failed to obtain session grouping parameter." << std::endl;
                                std::cout << tabs << result << std::endl;
                            }

                            LPWSTR iconPath;
                            result = p_audioControlSession->GetIconPath( &iconPath );
                            if ( SUCCEEDED( result.GetResult() ) )
                            {
                                std::cout << tabs << "Icon Path: ";
                                if ( iconPath && *iconPath )
                                {
                                    std::cout << iconPath << std::endl;
                                }
                                else
                                {
                                    std::cout << "Unknown" << std::endl;
                                }
                                CoTaskMemFree( iconPath );
                            }
                            else
                            {
                                std::cout << tabs << "Failed to obtain session icon path." << std::endl;
                                std::cout << tabs << result << std::endl;
                            }

                            AudioSessionState sessionState;
                            result = p_audioControlSession->GetState( &sessionState );
                            if ( SUCCEEDED( result.GetResult() ) )
                            {
                                std::cout << tabs << "Current Session State: " << sessionState << std::endl;
                            }
                            else
                            {
                                std::cout << tabs << "Failed to obtain session state." << std::endl;
                                std::cout << tabs << result << std::endl;
                            }


                            IAudioSessionControl2 *p_audioSessionControl2 = nullptr;
                            result = p_audioControlSession->QueryInterface( __uuidof( IAudioSessionControl2 ), reinterpret_cast< void ** >( &p_audioSessionControl2 ) );
                            p_audioControlSession->Release();
                            std::cout << std::endl;
                            if ( SUCCEEDED( result.GetResult() ) )
                            {
                                std::cout << tabs << "Extended control session data" << std::endl;
                                tabs.Inc();

                                LPWSTR displayName;
                                result = p_audioSessionControl2->GetDisplayName( &displayName );
                                if ( SUCCEEDED( result.GetResult() ) )
                                {
                                    std::cout << tabs << "Extended Display Name: ";
                                    if ( displayName && *displayName )
                                    {
                                        std::cout << displayName << std::endl;
                                    }
                                    else
                                    {
                                        std::cout << "Unknown" << std::endl;
                                    }
                                    CoTaskMemFree( displayName );
                                }
                                else
                                {
                                    std::cout << tabs << "Failed to obtain extended session display name." << std::endl;
                                    std::cout << tabs << result << std::endl;
                                }

                                result = p_audioSessionControl2->IsSystemSoundsSession();
                                if ( result == S_OK )
                                {
                                    std::cout << tabs << "The session is a system sounds session." << std::endl;
                                }
                                else if ( result == S_FALSE )
                                {
                                    std::cout << tabs << "The session is not a system sounds session" << std::endl;
                                }
                                else
                                {
                                    std::cout << tabs << "Undefined result. Conglaturations." << std::endl;
                                }

                                GUID groupingParam;
                                result = p_audioSessionControl2->GetGroupingParam( &groupingParam );
                                if ( SUCCEEDED( result.GetResult() ) )
                                {
                                    std::cout << tabs << "Grouping param: " << groupingParam << std::endl;
                                }
                                else
                                {
                                    std::cout << tabs << "Failed to obtain extended session groupin parameters." << std::endl;
                                    std::cout << tabs << result << std::endl;
                                }

                                LPWSTR iconPath;
                                result = p_audioSessionControl2->GetIconPath( &iconPath );
                                if ( SUCCEEDED( result.GetResult() ) )
                                {
                                    std::cout << tabs << "Icon Path: ";
                                    if ( iconPath && *iconPath )
                                    {
                                        std::cout << iconPath << std::endl;
                                    }
                                    else
                                    {
                                        std::cout << "Unknown" << std::endl;
                                    }
                                    CoTaskMemFree( iconPath );
                                }
                                else
                                {
                                    std::cout << tabs << "Failed to obtain extended session icon path." << std::endl;
                                    std::cout << tabs << result << std::endl;
                                }

                                DWORD processID;
                                result = p_audioSessionControl2->GetProcessId( &processID );
                                if ( SUCCEEDED( result.GetResult() ) )
                                {
                                    std::cout << tabs << "Process ID: " << processID << std::endl;
                                }
                                else
                                {
                                    std::cout << tabs << "Failed to obtain extended session process ID." << std::endl;
                                    std::cout << tabs << result << std::endl;
                                }

                                LPWSTR sessionIdentifier;
                                result = p_audioSessionControl2->GetSessionIdentifier( &sessionIdentifier );
                                if ( SUCCEEDED( result.GetResult() ) )
                                {
                                    std::cout << tabs << "Session ID: ";
                                    if ( sessionIdentifier && *sessionIdentifier )
                                    {
                                        std::cout << sessionIdentifier << std::endl;
                                    }
                                    else
                                    {
                                        std::cout << "Unknown" << std::endl;
                                    }
                                    CoTaskMemFree( sessionIdentifier );
                                }
                                else
                                {
                                    std::cout << tabs << "Failed to obtain extended session session ID." << std::endl;
                                    std::cout << tabs << result << std::endl;
                                }

                                LPWSTR sessionInstanceIdentifier;
                                result = p_audioSessionControl2->GetSessionInstanceIdentifier( &sessionInstanceIdentifier );
                                if ( SUCCEEDED( result.GetResult() ) )
                                {
                                    std::cout << tabs << "Session Instance ID: ";
                                    if ( sessionInstanceIdentifier && *sessionInstanceIdentifier )
                                    {
                                        std::cout << sessionInstanceIdentifier << std::endl;
                                    }
                                    else
                                    {
                                        std::cout << "Unknown" << std::endl;
                                    }
                                    CoTaskMemFree( sessionInstanceIdentifier );
                                }
                                else
                                {
                                    std::cout << tabs << "Failed to obtain extended session instance ID." << std::endl;
                                    std::cout << tabs << result << std::endl;
                                }

                                AudioSessionState audioSessionState;
                                result = p_audioSessionControl2->GetState( &audioSessionState );
                                if ( SUCCEEDED( result.GetResult() ) )
                                {
                                    std::cout << tabs << "Session State: " << audioSessionState << std::endl;
                                }
                                else
                                {
                                    std::cout << tabs << "Failed to obtain extended session session state." << std::endl;
                                    std::cout << tabs << result << std::endl;
                                }

                                tabs.Dec();
                                p_audioSessionControl2->Release();
                            }
                            else if ( result != E_NOINTERFACE )
                            {
                                std::cout << tabs << "Failed to scan Audio Session Data 2 Interface." << std::endl;
                                std::cout << tabs << result << std::endl;
                            }

                        }
                        else if ( result != E_NOINTERFACE )
                        {
                            std::cout << tabs << "Failed to scan Audio Session Data Interface." << std::endl;
                            std::cout << tabs << result << std::endl;
                        }

                        tabs.Dec();
                        std::cout << std::endl;
                    }

                    tabs.Dec();
                }

                sessionEnumerator->Release();
            }
            else
            {
                std::cout << tabs << "Failed to enumerate audio sessions." << std::endl;
                std::cout << tabs << result << std::endl;
            }

            tabs.Dec();
        }

        p_audioSessionManager2->Release();
    }
    else if ( result != E_NOINTERFACE )
    {
        std::cout << tabs << "Failed to scan Audio Session Manager 2 Interface." << std::endl;
        std::cout << tabs << result << std::endl;
    }

    IBaseFilter *p_baseFilter = nullptr;
    result = p_device->Activate( __uuidof( IBaseFilter ), CLSCTX_ALL, NULL, reinterpret_cast< void ** >( &p_baseFilter ) );
    if ( SUCCEEDED( result.GetResult() ) )
    {
        hasInterface = true;
        std::cout << tabs << "Audio Base Filter Interface" << std::endl;

        if ( verbose )
        {
            tabs.Inc();

            IEnumPins *p_basePins;
            result = p_baseFilter->EnumPins( &p_basePins );
            if ( SUCCEEDED( result.GetResult() ) )
            {
                int pinIdx = 1;
                IPin *p_basePin;
                result = p_basePins->Next( 1, &p_basePin, 0 );
                while ( result == S_OK )
                {
                    std::cout << tabs << "Pin " << pinIdx << std::endl;
                    tabs.Inc();

                    IPin *p_nextPin;
                    result = p_basePin->ConnectedTo( &p_nextPin );
                    if ( SUCCEEDED( result.GetResult() ) )
                    {
                        LPWSTR adjacentId;
                        result = p_nextPin->QueryId( &adjacentId );
                        if ( SUCCEEDED( result.GetResult() ) )
                        {
                            std::cout << tabs << "Connected to: ";
                            if ( adjacentId && *adjacentId )
                            {
                                std::cout << adjacentId << std::endl;
                            }
                            else
                            {
                                std::cout << "Unknown" << std::endl;
                            }
                            CoTaskMemFree( adjacentId );
                        }
                        else
                        {
                            std::cout << tabs << "Failed to get ID of the adjacent pin." << std::endl;
                            std::cout << tabs << result << std::endl;
                        }
                        p_nextPin->Release();
                    }
                    else
                    {
                        std::cout << tabs << "Failed to obtain adjacent pin." << std::endl;
                        std::cout << tabs << result << std::endl;
                    }

                    AM_MEDIA_TYPE basePinMediaType;
                    result = p_basePin->ConnectionMediaType( &basePinMediaType );
                    if ( SUCCEEDED( result.GetResult() ) )
                    {
                        std::cout << tabs << "Base media Type: " << std::endl;
                        tabs.Inc();

                        std::cout << tabs << "Major type: " << basePinMediaType.majortype << std::endl;
                        std::cout << tabs << "Subtype: " << basePinMediaType.subtype << std::endl;
                        std::cout << tabs << "Sample Size: " << basePinMediaType.lSampleSize << std::endl;
                        std::cout << tabs << "Format Type: " << basePinMediaType.formattype << std::endl;
                        std::cout << tabs << "Format Size: " << basePinMediaType.cbFormat << " bytes" << std::endl;
                        std::cout << tabs << "Fixed Sample Size: " << ( basePinMediaType.bFixedSizeSamples ? "true" : "false" ) << std::endl;
                        std::cout << tabs << "Uses Temporal compression: " << ( basePinMediaType.bTemporalCompression ? "true" : "false" ) << std::endl;

                        tabs.Dec();
                        _FreeMediaType( basePinMediaType );
                    }
                    else
                    {
                        std::cout << tabs << "Failed to obtain base pin media type." << std::endl;
                        std::cout << tabs << result << std::endl;
                    }

                    IEnumMediaTypes *p_baseMediaTypeEnum;
                    result = p_basePin->EnumMediaTypes( &p_baseMediaTypeEnum );
                    if ( SUCCEEDED( result.GetResult() ) )
                    {
                        std::cout << tabs << "Other known media types: " << std::endl;
                        tabs.Inc();

                        AM_MEDIA_TYPE *p_baseMediaType;
                        result = p_baseMediaTypeEnum->Next( 1, &p_baseMediaType, 0 );
                        while ( result == S_OK )
                        {
                            std::cout << tabs << "Base media Type: " << std::endl;
                            tabs.Inc();

                            std::cout << tabs << "Major type: " << p_baseMediaType->majortype << std::endl;
                            std::cout << tabs << "Subtype: " << p_baseMediaType->subtype << std::endl;
                            std::cout << tabs << "Sample Size: " << p_baseMediaType->lSampleSize << std::endl;
                            std::cout << tabs << "Format Type: " << p_baseMediaType->formattype << std::endl;
                            std::cout << tabs << "Format Size: " << p_baseMediaType->cbFormat << " bytes" << std::endl;
                            std::cout << tabs << "Fixed Sample Size: " << ( p_baseMediaType->bFixedSizeSamples ? "true" : "false" ) << std::endl;
                            std::cout << tabs << "Uses Temporal compression: " << ( p_baseMediaType->bTemporalCompression ? "true" : "false" ) << std::endl;

                            tabs.Dec();
                            _DeleteMediaType( p_baseMediaType );
                            result = p_baseMediaTypeEnum->Next( 1, &p_baseMediaType, 0 );
                        }

                        tabs.Dec();
                        p_baseMediaTypeEnum->Reset();
                        p_baseMediaTypeEnum->Release();
                    }
                    else
                    {
                        std::cout << tabs << "Failed to obtain list of base pin media types." << std::endl;
                        std::cout << tabs << result << std::endl;
                    }

                    PIN_DIRECTION basePinDirection;
                    result = p_basePin->QueryDirection( &basePinDirection );
                    if ( SUCCEEDED( result.GetResult() ) )
                    {
                        std::cout << tabs << "Current pin direction: " << basePinDirection << std::endl;
                    }
                    else
                    {
                        std::cout << tabs << "Failed to obtain pin direction." << std::endl;
                        std::cout << tabs << result << std::endl;
                    }

                    LPWSTR p_basePinId;
                    result = p_basePin->QueryId( &p_basePinId );
                    if ( SUCCEEDED( result.GetResult() ) )
                    {
                        std::cout << tabs << "Current pin ID: ";
                        if ( p_basePinId && *p_basePinId )
                        {
                            std::cout << p_basePinId << std::endl;
                        }
                        else
                        {
                            std::cout << "Unknown" << std::endl;
                        }
                        CoTaskMemFree( p_basePinId );
                    }
                    else
                    {
                        std::cout << tabs << "Failed to obtain current pin ID." << std::endl;
                        std::cout << tabs << result << std::endl;
                    }

                    PIN_INFO basePinInfo;
                    result = p_basePin->QueryPinInfo( &basePinInfo );
                    if ( SUCCEEDED( result.GetResult() ) )
                    {
                        CLSID owner;
                        if ( basePinInfo.pFilter )
                        {
                            if ( SUCCEEDED( basePinInfo.pFilter->GetClassID( &owner ) ) )
                            {
                                std::cout << tabs << "Owned by: " << owner << std::endl;
                            }
                            else
                            {
                                std::cout << tabs << "Failed to obtain filter class id." << std::endl;
                                std::cout << tabs << result << std::endl;
                            }
                        }
                    }
                    else
                    {
                        std::cout << tabs << "Failed to obtain current pin info." << std::endl;
                        std::cout << tabs << result << std::endl;
                    }

                    tabs.Dec();
                    result = p_basePins->Next( 1, &p_basePin, 0 );
                }

                p_basePins->Reset();
                p_basePins->Release();
            }
            else
            {
                std::cout << tabs << "Failed to enumerate base filter pins." << std::endl;
                std::cout << tabs << result << std::endl;
            }

            CLSID baseClassId;
            result = p_baseFilter->GetClassID( &baseClassId );
            if ( SUCCEEDED( result.GetResult() ) )
            {
                std::cout << tabs << "Base Class ID: " << baseClassId << std::endl;
            }
            else
            {
                std::cout << tabs << "Failed to obtain base class ID." << std::endl;
                std::cout << tabs << result << std::endl;
            }

            FILTER_STATE baseFilterState;
            result = p_baseFilter->GetState( 0, &baseFilterState );
            if ( SUCCEEDED( result.GetResult() ) )
            {
                std::cout << tabs << "Base Filter State: " << baseFilterState << std::endl;
            }
            else
            {
                std::cout << tabs << "Failed to obtain base filter state." << std::endl;
                std::cout << tabs << result << std::endl;
            }

            IReferenceClock *p_baseReferenceClock;
            result = p_baseFilter->GetSyncSource( &p_baseReferenceClock );
            if ( SUCCEEDED( result.GetResult() ) )
            {
                if ( p_baseReferenceClock )
                {
                    REFERENCE_TIME baseReferenceTime;
                    result = p_baseReferenceClock->GetTime( &baseReferenceTime );
                    if ( SUCCEEDED( result.GetResult() ) )
                    {
                        std::cout << tabs << "Base Clock Reference Time: " << baseReferenceTime << std::endl;
                    }
                    else
                    {
                        std::cout << tabs << "Failed to obtain reference clock time." << std::endl;
                        std::cout << tabs << result << std::endl;
                    }
                    p_baseReferenceClock->Release();
                }
                else
                {
                    std::cout << tabs << "Base filter has no reference clock." << std::endl;
                }
            }
            else
            {
                std::cout << tabs << "Failed to obtain base reference clock." << std::endl;
                std::cout << tabs << result << std::endl;
            }

            FILTER_INFO baseFilterInfo;
            result = p_baseFilter->QueryFilterInfo( &baseFilterInfo );
            if ( SUCCEEDED( result.GetResult() ) )
            {
                char szName[MAX_FILTER_NAME];
                int cch = WideCharToMultiByte(CP_ACP, 0, baseFilterInfo.achName,
                                               MAX_FILTER_NAME, szName, MAX_FILTER_NAME, 0, 0);
                if ( cch > 0 )
                {
                    std::cout << tabs << "Base filter name: ";
                    if ( szName && *szName )
                    {
                        std::cout << szName << std::endl; 
                    }
                    else
                    {
                        std::cout << "Unkown Filter Name" << std::endl;
                    }
                }

                if ( baseFilterInfo.pGraph )
                {
                    baseFilterInfo.pGraph->Release();
                }
            }
            else
            {
                std::cout << tabs << "Failed to obtain base filter info." << std::endl;
                std::cout << tabs << result << std::endl;
            }

            LPWSTR p_baseVendorInfo;
            std::cout << tabs << "Base vendor Info: " ;
            result = p_baseFilter->QueryVendorInfo( &p_baseVendorInfo );
            if ( SUCCEEDED( result.GetResult() ) )
            {
                if ( p_baseVendorInfo && *p_baseVendorInfo )
                {
                    std::cout << p_baseVendorInfo << std::endl;
                }
                else
                {
                    std::cout << "Unknown" << std::endl;
                }
                CoTaskMemFree( p_baseVendorInfo );
            }
            else if ( result == E_NOTFOUND || result == E_NOTIMPL )
            {
                std::cout << "Not provided." << std::endl;
            }
            else
            {
                std::cout << "Failed to obtain vendor info." << std::endl;
                std::cout << tabs << result << std::endl;
            }

            tabs.Dec();
        }

        p_baseFilter->Release();
    }
    else if ( result != E_NOINTERFACE )
    {
        std::cout << tabs << "Failed to scan Audio Base Filter Interface." << std::endl;
        std::cout << tabs << result << std::endl;
    }

    IMFTrustedOutput *p_mfTrustedOutput = nullptr;
    result = p_device->Activate( __uuidof( IMFTrustedOutput ), CLSCTX_ALL, NULL, reinterpret_cast< void ** >( &p_mfTrustedOutput ) );
    if ( SUCCEEDED( result.GetResult() ) )
    {
        hasInterface = true;
        std::cout << tabs << "Media Foundation Transform Trusted Output Interface" << std::endl;

        if ( verbose )
        {
            tabs.Inc();

            DWORD trustedOutputCount = 0;
            result = p_mfTrustedOutput->GetOutputTrustAuthorityCount( &trustedOutputCount );
            if ( SUCCEEDED( result.GetResult() ) )
            {
                std::cout << tabs << "Output is trusted with the following:" << std::endl;
                tabs.Inc();

                for ( DWORD trustedOutputIdx = 0; trustedOutputIdx < trustedOutputCount; trustedOutputIdx++ )
                {
                    IMFOutputTrustAuthority *p_imfOutputTrustAuthority;
                    result = p_mfTrustedOutput->GetOutputTrustAuthorityByIndex( trustedOutputIdx, &p_imfOutputTrustAuthority );
                    if ( SUCCEEDED( result.GetResult() ) )
                    {
                        MFPOLICYMANAGER_ACTION trustedOutputTrustAction;
                        result = p_imfOutputTrustAuthority->GetAction( &trustedOutputTrustAction );

                        if ( SUCCEEDED( result.GetResult() ) )
                        {
                            std::cout << tabs << (trustedOutputIdx + 1) << ": " << trustedOutputTrustAction << std::endl;
                        }
                        else
                        {
                            std::cout << tabs << "Failed to obtain trusted action." << std::endl;
                            std::cout << tabs << result << std::endl;
                        }

                        p_imfOutputTrustAuthority->Release();
                    }
                    else
                    {
                        std::cout << tabs << "Failed to obtain trusted action details." << std::endl;
                        std::cout << tabs << result << std::endl;
                    }
                }

                tabs.Dec();
            }
            else
            {
                std::cout << tabs << "Failed to obtain trusted actions." << std::endl;
                std::cout << tabs << result << std::endl;
            }

            BOOL trustedOutputIsFinal = FALSE;
            result = p_mfTrustedOutput->IsFinal( &trustedOutputIsFinal );
            if ( SUCCEEDED( result.GetResult() ) )
            {
                if ( trustedOutputIsFinal )
                {
                    std::cout << tabs << "Final trusted output. Device is a \"Policy Sink\"" << std::endl;
                }
            }
            else
            {
                std::cout << tabs << "Failed to determine if device is the final trusted output." << std::endl;
                std::cout << tabs << result << std::endl;
            }

            tabs.Dec();
        }

        p_mfTrustedOutput->Release();
    }
    else if ( result != E_NOINTERFACE )
    {
        std::cout << tabs << "Failed to scan Media Foundation Transform Trusted Output Interface." << std::endl;
        std::cout << tabs << result << std::endl;
    }

    IDeviceTopology *p_deviceTopology = nullptr;
    result = p_device->Activate( __uuidof( IDeviceTopology ), CLSCTX_ALL, NULL, reinterpret_cast< void ** >( &p_deviceTopology ) );
    if ( SUCCEEDED( result.GetResult() ) )
    {
        hasInterface = true;
        std::cout << tabs << "Device Topology Interface" << std::endl;

        if ( verbose )
        {
            tabs.Inc();

            LPWSTR deviceTopologyId = nullptr;
            result = p_deviceTopology->GetDeviceId( &deviceTopologyId );
            if ( SUCCEEDED( result.GetResult() ) )
            {
                std::cout << tabs << "Device Topology ID: ";
                if ( deviceTopologyId && *deviceTopologyId )
                {
                    std::cout << deviceTopologyId << std::endl;
                }
                else
                {
                    std::cout << "Unknown" << std::endl;
                }
                CoTaskMemFree( deviceTopologyId );
            }
            else
            {
                std::cout << tabs << "Unable to obtain topology device ID." << std::endl;
                std::cout << tabs << result << std::endl;
            }

            UINT connectorCount = 0;
            result = p_deviceTopology->GetConnectorCount( &connectorCount );
            if ( SUCCEEDED( result.GetResult() ) )
            {
                std::cout << tabs << "Device has " << connectorCount << " connectors." << std::endl;
                tabs.Inc();
            
                for ( UINT connectorIdx = 0; connectorIdx < connectorCount; connectorIdx++ )
                {
                    std::cout << tabs << "Connection " << connectorIdx + 1 << std::endl;
                    tabs.Inc();

                    IConnector *p_connector = nullptr;
                    result = p_deviceTopology->GetConnector( connectorIdx, &p_connector );
                    if ( SUCCEEDED( result.GetResult() ) )
                    {
                        ConnectorType connectorType;
                        result = p_connector->GetType( &connectorType );
                        if ( SUCCEEDED( result.GetResult() ) )
                        {
                            std::cout << tabs << "Connection Type: " << connectorType << std::endl;
                        }
                        else
                        {
                            std::cout << tabs << "Unable to determine connection type." << std::endl;
                            std::cout << tabs << result << std::endl;
                        }

                        DataFlow dataFlow = DataFlow::In;
                        result = p_connector->GetDataFlow( &dataFlow );
                        if ( SUCCEEDED( result.GetResult() ) )
                        {
                            std::cout << tabs << "Connection Direction: " << dataFlow << std::endl;
                        }
                        else
                        {
                            std::cout << tabs << "Unable to determine connection direction." << std::endl;
                            std::cout << tabs << result << std::endl;
                        }
                    }
                    else
                    {
                        std::cout << tabs << "Unable to obtain topology connection." << std::endl;
                        std::cout << tabs << result << std::endl;
                    }

                    tabs.Dec();
                    p_connector->Release();
                    std::cout << std::endl;
                }

                tabs.Dec();
            }

            tabs.Dec();
        }

        p_deviceTopology->Release();
    }
    else if ( result != E_NOINTERFACE )
    {
        std::cout << tabs << "Failed to scan Device Topology Interface." << std::endl;
        std::cout << tabs << result << std::endl;
    }

    if ( hasInterface == false )
    {
        std::cout << tabs << "No device interfaces detected." << std::endl;
    }
}


static void ScanPartName( IPart *p_part )
{
    MyResult result = S_OK;
    Tabs tabs;

    LPWSTR p_partName = nullptr;
    result = p_part->GetName( &p_partName );
    if ( SUCCEEDED( result.GetResult() ) )
    {
        std::cout << tabs << "Name: ";
        if ( p_partName && *p_partName )
        {
            std::cout << p_partName << std::endl;
        }
        else
        {
            std::cout << "Unknown" << std::endl;
        }

        CoTaskMemFree( p_partName );
    }
    else
    {
        std::cout << tabs << "Failed to obtain part name." << std::endl;
        std::cout << tabs << result << std::endl;
    }

    if ( verbose )
    {
        UINT partLocalID = 0;
        result = p_part->GetLocalId( &partLocalID );
        if ( SUCCEEDED( result.GetResult() ) )
        {
            std::cout << tabs << "Local Id: "
                << std::hex
                << "0x"
                << partLocalID 
                << std::dec 
                << std::endl;
        }
        else
        {
            std::cout << tabs << "Failed to obtain part local ID." << std::endl;
            std::cout << tabs << result << std::endl;
        }

        PartType partType;
        result = p_part->GetPartType( &partType );
        if ( SUCCEEDED( result.GetResult() ) )
        {
            std::cout << tabs << "Type: " << partType << std::endl;
        }
        else
        {
            std::cout << tabs << "Failed to obtain part type." << std::endl;
            std::cout << tabs << result << std::endl;
        }

        GUID subType;
        result = p_part->GetSubType( &subType );
        if ( SUCCEEDED( result.GetResult() ) )
        {
            std::cout << tabs << "Sub-Type: " << subType << std::endl;
        }
        else
        {
            std::cout << tabs << "Failed to obtain part sub-type." << std::endl;
            std::cout << tabs << result << std::endl;
        }
    }
}


static void ScanPartInterfaces( IPart *p_part )
{
    GUID        partSubType;
    UINT        partLocalId = 0;
    PartType    partType    = Connector;
    MyResult     result      = S_OK;
    Tabs tabs;

    std::memset( &partSubType, 0, sizeof( partSubType ) );

    bool hasInterface = false;

    IAudioAutoGainControl *gainControl  = nullptr;
    result = p_part->Activate( CLSCTX_ALL, __uuidof( IAudioAutoGainControl ), reinterpret_cast< void** >( &gainControl ) );
    if ( SUCCEEDED( result.GetResult() ) )
    {
        hasInterface = true;
        std::cout << tabs << "Audio Auto Gain Control Interface" << std::endl;

        if ( verbose )
        {
            tabs.Inc();

            BOOL enabled = FALSE;
            result = gainControl->GetEnabled( &enabled );
            if ( SUCCEEDED( result.GetResult() ) )
            {
                std::cout << tabs << (enabled ? "Enabled" : "Disabled") << std::endl;
            }
            else
            {
                std::cout << tabs << "Cannot determine if enabled or disabled." << std::endl;
                std::cout << tabs << result << std::endl;
            }

            tabs.Dec();
        }

        gainControl->Release();
    }
    else if ( result != E_NOINTERFACE )
    {
        std::cout << tabs << "Failed to scan Audio Auto Gain Control interface." << std::endl;
        std::cout << tabs << result << std::endl;
    }

    IAudioBass *bass = nullptr;
    result = p_part->Activate( CLSCTX_ALL, __uuidof( IAudioBass ), reinterpret_cast< void **>( &bass ) );
    if ( SUCCEEDED( result.GetResult() ) )
    {
        hasInterface = true;
        std::cout << tabs << "Audio Bass Interface" << std::endl;
        
        if ( verbose )
        {
            tabs.Inc();

            UINT channelCount = 0;
            result = bass->GetChannelCount( &channelCount );
            if ( SUCCEEDED( result.GetResult() ) )
            {
                std::cout << tabs << "Detected " << channelCount << " channels." << std::endl;
                tabs.Inc();

                for ( UINT bassChannelIdx = 0; bassChannelIdx < channelCount; ++bassChannelIdx )
                {
                    std::cout << tabs << "Channel " << bassChannelIdx + 1 << std::endl;
                    tabs.Inc();

                    float level = 0.0f;
                    float min   = 0.0f;
                    float max   = 0.0f;
                    float step  = 0.0f;

                    result = bass->GetLevel( bassChannelIdx, &level );
                    if ( SUCCEEDED( result.GetResult() ) )
                    {
                        std::cout << tabs << "Level : " << level << std::endl;
                    }
                    else
                    {
                        std::cout << tabs << "Failed to obtain bass channel level." << std::endl;
                        std::cout << tabs << result << std::endl;
                    }

                    result = bass->GetLevelRange( bassChannelIdx, &min, &max, &step );
                    if ( SUCCEEDED( result.GetResult() ) )
                    {
                        std::cout << tabs << "Min   : " << min << std::endl;
                        std::cout << tabs << "Max   : " << max << std::endl;
                        std::cout << tabs << "Step  : " << step << std::endl;
                    }
                    else
                    {
                        std::cout << tabs << "Failed to obtain bass channel level range." << std::endl;
                        std::cout << tabs << result << std::endl;
                    }

                    tabs.Dec();
                }

                tabs.Dec();
            }
            else
            {
                std::cout << tabs << "Failed to obtain bass channel count." << std::endl;
                std::cout << tabs << result << std::endl;
            }

            tabs.Dec();
        }

        bass->Release();
    }
    else if ( result != E_NOINTERFACE )
    {
        std::cout << tabs << "Failed to scan Audio Bass interface." << std::endl;
        std::cout << tabs << result << std::endl;
    }

    IAudioMidrange *midRange = nullptr;
    result = p_part->Activate( CLSCTX_ALL, __uuidof( IAudioMidrange ), reinterpret_cast< void ** >( &midRange ) );
    if ( SUCCEEDED( result.GetResult() ) )
    {
        hasInterface = true;
        std::cout << tabs << "Audio Midrange Interface" << std::endl;

        if ( verbose )
        {
            tabs.Inc();

            UINT midRangeChannelCount = 0;
            result = midRange->GetChannelCount( &midRangeChannelCount );
            if ( SUCCEEDED( result.GetResult() ) )
            {
                std::cout << tabs << "Detected " << midRangeChannelCount << " channels." << std::endl;
                tabs.Inc();

                for ( UINT midRangeChannelIdx = 0; midRangeChannelIdx < midRangeChannelCount; ++midRangeChannelIdx )
                {
                    std::cout << tabs << "Channel " << midRangeChannelIdx + 1 << std::endl;
                    tabs.Inc();

                    float level = 0.0f;
                    float min   = 0.0f;
                    float max   = 0.0f;
                    float step  = 0.0f;

                    result = midRange->GetLevel( midRangeChannelIdx, &level );
                    if ( SUCCEEDED( result.GetResult() ) )
                    {
                        std::cout << tabs << "Level : " << level << std::endl;
                    }
                    else
                    {
                        std::cout << tabs << "Failed to obtain midrange channel level." << std::endl;
                        std::cout << tabs << result << std::endl;
                    }

                    result  = midRange->GetLevelRange( midRangeChannelIdx, &min, &max, &step );
                    if ( SUCCEEDED( result.GetResult() ) )
                    {
                        std::cout << tabs << "Min   : " << min << std::endl;
                        std::cout << tabs << "Max   : " << max << std::endl;
                        std::cout << tabs << "Step  : " << step << std::endl;
                    }
                    else
                    {
                        std::cout << tabs << "Failed to obtain midrange channel level ranges." << std::endl;
                        std::cout << tabs << result << std::endl;
                    }

                    tabs.Dec();
                }

                tabs.Dec();
            }
            else
            {
                std::cout << tabs << "Failed to obtain midrange channel count." << std::endl;
                std::cout << tabs << result << std::endl;
            }

            tabs.Dec();
        }

        midRange->Release();
    }
    else if ( result != E_NOINTERFACE )
    {
        std::cout << tabs << "Failed to scan Audio Bass interface." << std::endl;
        std::cout << tabs << result << std::endl;
    }

    IAudioTreble *treble = nullptr;
    result = p_part->Activate( CLSCTX_ALL, __uuidof( IAudioTreble ), reinterpret_cast< void ** >( &treble ) );
    if ( SUCCEEDED( result.GetResult() ) )
    {
        hasInterface = true;
        std::cout << tabs << "Audio Treble Interface" << std::endl;

        if ( verbose )
        {
            tabs.Inc();

            UINT trebleChannelCount = 0;
            result = treble->GetChannelCount( &trebleChannelCount );
            if ( SUCCEEDED( result.GetResult() ) )
            {
                std::cout << tabs << "Detected " << trebleChannelCount << " channels." << std::endl;
                tabs.Inc();

                for ( UINT trebleChannelIdx = 0; trebleChannelIdx < trebleChannelCount; ++trebleChannelIdx )
                {
                    std::cout << tabs << "Channel " << trebleChannelIdx + 1 << std::endl;
                    tabs.Inc();

                    float level = 0.0f;
                    float min   = 0.0f;
                    float max   = 0.0f;
                    float step  = 0.0f;

                    result = treble->GetLevel( trebleChannelIdx, &level );
                    if ( SUCCEEDED( result.GetResult() ) )
                    {
                        std::cout << tabs << "Level : " << level << std::endl;
                    }
                    else
                    {
                        std::cout << tabs << "Failed to obtain treble channel level." << std::endl;
                        std::cout << tabs << result << std::endl;
                    }

                    result = treble->GetLevelRange( trebleChannelIdx, &min, &max, &step );
                    if ( SUCCEEDED( result.GetResult() ) )
                    {
                        std::cout << tabs << "Min   : " << min << std::endl;
                        std::cout << tabs << "Max   : " << max << std::endl;
                        std::cout << tabs << "Step  : " << step << std::endl;
                    }
                    else
                    {
                        std::cout << tabs << "Failed to obtain treble channel level ranges." << std::endl;
                        std::cout << tabs << result << std::endl;
                    }

                    tabs.Dec();
                }

                tabs.Dec();
            }
            else
            {
                std::cout << tabs << "Failed to obtain treble channel count." << std::endl;
                std::cout << tabs << result << std::endl;
            }

            tabs.Dec();
        }

        treble->Release();
    }
    else if ( result != E_NOINTERFACE )
    {
        std::cout << tabs << "Failed to scan Audio Bass interface." << std::endl;
        std::cout << tabs << result << std::endl;
    }

    IAudioChannelConfig *chanConfig = nullptr;
    result = p_part->Activate( CLSCTX_ALL, __uuidof( IAudioChannelConfig ), reinterpret_cast< void** >( &chanConfig ) );
    if ( SUCCEEDED( result.GetResult() ) )
    {
        hasInterface = true;
        std::cout << tabs << "Audio Channel Configuration Interface" << std::endl;

        if ( verbose )
        {
            tabs.Inc();

            DWORD config = 0;
            result = chanConfig->GetChannelConfig( &config );
            if ( SUCCEEDED( result.GetResult() ) )
            {
                std::cout << tabs << "Configuration Mask: " 
                    << std::hex 
                    << "0x" 
                    << config 
                    << std::dec 
                    << std::endl;

                ScanChannelConfiguration( config );

                tabs.Inc();

                GUID partSubType;
                result = p_part->GetSubType( &partSubType );
                if ( SUCCEEDED( result.GetResult() ) )
                {
                    if ( IsEqualGUID( KSNODETYPE_3D_EFFECTS, partSubType ) == TRUE )
                    {
                        std::cout << tabs << "3D-effects processor for the device-specific 3D hardware acceleration layer." << std::endl;

                        tabs.Inc();

                        std::cout << tabs << "One input stream, with either one or two channels." << std::endl;
                        std::cout << tabs << "One output stream, with any number of channels." << std::endl;

                        tabs.Dec();

                    }
                    if ( IsEqualGUID( KSNODETYPE_DAC, partSubType ) == TRUE )
                    {
                        std::cout << tabs << "Digital-to-Analog converter" << std::endl;

                        tabs.Inc();

                        std::cout << tabs << "One input stream." << std::endl;
                        std::cout << tabs << "One output stream." << std::endl;

                        tabs.Dec();
                    }
                    if ( IsEqualGUID( KSNODETYPE_VOLUME, partSubType ) == TRUE )
                    {
                        std::cout << tabs << "Volume (gain or attenuation) control" << std::endl;

                        tabs.Inc();

                        std::cout << tabs << "One input stream." << std::endl;
                        std::cout << tabs << "One output stream." << std::endl;

                        tabs.Dec();
                    }
                    if ( IsEqualGUID( KSNODETYPE_PROLOGIC_DECODER, partSubType ) == TRUE )
                    {
                        std::cout << tabs << "Dolby Surround Pro Logic decoder" << std::endl;

                        tabs.Inc();

                        std::cout << tabs << "One stereo input stream." << std::endl;
                        std::cout << tabs << "One output stream." << std::endl;

                        tabs.Inc();

                        std::cout << tabs << "Four-Channel Format:" << std::endl;

                        tabs.Inc();

                        std::cout << tabs << "Left" << std::endl;
                        std::cout << tabs << "Right" << std::endl;
                        std::cout << tabs << "Center" << std::endl;
                        std::cout << tabs << "Back" << std::endl;

                        tabs.Dec();

                        std::cout << tabs << "Three-Channel Format:" << std::endl;

                        tabs.Inc();

                        std::cout << tabs << "Left" << std::endl;
                        std::cout << tabs << "Right" << std::endl;
                        std::cout << tabs << "Back" << std::endl;

                        tabs.Dec();

                        tabs.Dec();

                        tabs.Dec();
                    }
                }
                else
                {
                    std::cout << tabs << "Failed to get configuration ID." << std::endl;
                    std::cout << tabs << result << std::endl;
                }

                tabs.Dec();
            }
            else
            {
                std::cout << tabs << "Failed to determine channel configuration." << std::endl;
                std::cout << tabs << result << std::endl;
            }

            tabs.Dec();
        }

        chanConfig->Release();
    }
    else if ( result != E_NOINTERFACE )
    {
        std::cout << tabs << "Failed to scan Audio Channel Configuration Interface." << std::endl;
        std::cout << tabs << result << std::endl;
    }

    IAudioInputSelector *inSelector = nullptr;
    result = p_part->Activate( CLSCTX_ALL, __uuidof( IAudioInputSelector ), reinterpret_cast< void** >( &inSelector ) );
    if ( SUCCEEDED( result.GetResult() ) )
    {
        hasInterface = true;
        std::cout << tabs << "Audio Input Selector Interface" << std::endl;

        if ( verbose )
        {
            tabs.Inc();

            UINT selection = 0;
            result = inSelector->GetSelection( &selection );
            if ( SUCCEEDED( result.GetResult() ) )
            {
                std::cout << tabs << "Part " 
                    << std::hex 
                    << "0x" 
                    << selection 
                    << std::dec 
                    << " is currently selected." 
                    << std::endl;

                GUID partSubType;
                result = p_part->GetSubType( &partSubType );
                if ( SUCCEEDED( result.GetResult() ) )
                {
                    // https://msdn.microsoft.com/en-us/library/windows/hardware/ff537163(v=vs.85).aspx
                    if ( IsEqualGUID( KSNODETYPE_DEMUX, partSubType ) == TRUE )
                    {
                        IDeviceTopology *p_topology = nullptr;
                        result = p_part->Activate( CLSCTX_ALL, __uuidof( IDeviceTopology ), reinterpret_cast< void ** >( &p_topology ) );
                        if ( SUCCEEDED( result.GetResult() ) )
                        {
                            IPart *p_selectedPart = nullptr;
                            result = p_topology->GetPartById( selection, &p_selectedPart );
                            if ( SUCCEEDED( result.GetResult() ) )
                            {
                                std::cout << "Inputs from... " << std::endl;
                                tabs.Inc();

                                ScanPartName( p_part );
                                tabs.Dec();
                            }
                            else
                            {
                                std::cout << tabs << "Failed to get connected part." << std::endl;
                                std::cout << tabs << result << std::endl;
                            }
                            p_topology->Release();
                        }
                        else
                        {
                            std::cout << tabs << "Failed get device topology." << std::endl;
                            std::cout << tabs << result << std::endl;
                        }
                    }
                }
                else
                {
                    std::cout << tabs << "Failed to get input ID." << std::endl;
                    std::cout << tabs << result << std::endl;
                }
            }
            else
            {
                std::cout << tabs << "Failed to determine selection configuration." << std::endl;
                std::cout << tabs << result << std::endl;
            }

            tabs.Dec();
        }

        inSelector->Release();
    }
    else if ( result != E_NOINTERFACE )
    {
        std::cout << tabs << "Failed to scan Audio Input Selector Interface." << std::endl;
        std::cout << tabs << result << std::endl;
    }

    IAudioOutputSelector *outSelect = nullptr;
    result = p_part->Activate( CLSCTX_ALL, __uuidof( IAudioOutputSelector ), reinterpret_cast< void** >( &outSelect ) );
    if ( SUCCEEDED( result.GetResult() ) )
    {
        hasInterface = true;
        std::cout << tabs << "Audio Output Selector Interface" << std::endl;

        if ( verbose )
        {
            tabs.Inc();

            UINT selection = 0;
            result = outSelect->GetSelection( &selection );
            if ( SUCCEEDED( result.GetResult() ) )
            {
                std::cout << tabs << "Part " 
                    << std::hex 
                    << "0x" 
                    << selection 
                    << std::dec 
                    << " is currently selected." 
                    << std::endl;

                GUID partSubType;
                result = p_part->GetSubType( &partSubType );
                if ( SUCCEEDED( result.GetResult() ) )
                {
                    // https://msdn.microsoft.com/en-us/library/windows/hardware/ff537163(v=vs.85).aspx
                    if ( IsEqualGUID( KSNODETYPE_DEMUX, partSubType ) == TRUE )
                    {
                        IDeviceTopology *p_topology = nullptr;
                        result = p_part->Activate( CLSCTX_ALL, __uuidof( IDeviceTopology ), reinterpret_cast< void ** >( &p_topology ) );
                        if ( SUCCEEDED( result.GetResult() ) )
                        {
                            IPart *p_selectedPart = nullptr;
                            result = p_topology->GetPartById( selection, &p_selectedPart );
                            if ( SUCCEEDED( result.GetResult() ) )
                            {
                                std::cout << "Outputs to... " << std::endl;
                                tabs.Inc();

                                ScanPartName( p_part );
                                tabs.Dec();
                            }
                            else
                            {
                                std::cout << tabs << "Failed to get connected part." << std::endl;
                                std::cout << tabs << result << std::endl;
                            }
                            p_topology->Release();
                        }
                        else
                        {
                            std::cout << tabs << "Failed get device topology." << std::endl;
                            std::cout << tabs << result << std::endl;
                        }
                    }
                }
                else
                {
                    std::cout << tabs << "Failed to get output ID." << std::endl;
                    std::cout << tabs << result << std::endl;
                }
            }
            else
            {
                std::cout << tabs << "Failed to get connected output." << std::endl;
                std::cout << tabs << result << std::endl;
            }

            tabs.Dec();
        }

        outSelect->Release();
    }
    else if ( result != E_NOINTERFACE )
    {
        std::cout << tabs << "Failed to scan Audio output Selector Interface." << std::endl;
        std::cout << tabs << result << std::endl;
    }

    IAudioLoudness *loudness = nullptr;
    result = p_part->Activate( CLSCTX_ALL, __uuidof( IAudioLoudness ), reinterpret_cast< void ** >( &loudness ) );
    if ( SUCCEEDED( result.GetResult() ) )
    {
        hasInterface = true;
        std::cout << tabs << "Audio Loudness Interface" << std::endl;
        
        if ( verbose )
        {
            tabs.Inc();

            BOOL enabled = FALSE;
            result  = loudness->GetEnabled( &enabled );
            if ( SUCCEEDED( result.GetResult() ) )
            {
                std::cout << tabs << ( enabled ? "Enabled" : "Disabled" ) << std::endl;
            }
            else
            {
                std::cout << tabs << "Cannot determine if enabled or disabled." << std::endl;
                std::cout << tabs << result << std::endl;
            }

            tabs.Dec();
        }

        loudness->Release();
    }
    else if ( result != E_NOINTERFACE )
    {
        std::cout << tabs << "Failed to scan Audio Loudness Interface." << std::endl;
        std::cout << tabs << result << std::endl;
    }

    IAudioMute *mute  = nullptr;
    result = p_part->Activate( CLSCTX_ALL, __uuidof( IAudioMute ), reinterpret_cast< void **>( &mute ) );
    if ( SUCCEEDED( result.GetResult() ) )
    {
        hasInterface = true;
        std::cout << tabs << "Audio Mute Interface" << std::endl;

        if ( verbose )
        {
            tabs.Inc();

            BOOL muted = FALSE;
            result = mute->GetMute( &muted );
            if ( SUCCEEDED( result.GetResult() ) )
            {
                std::cout << tabs << (muted ? "Enabled" : "Disabled") << std::endl;
            }
            else
            {
                std::cout << tabs << "Cannot determine if enabled or disabled." << std::endl;
                std::cout << tabs << result << std::endl;
            }

            tabs.Dec();
        }

        mute->Release();
    }
    else if ( result != E_NOINTERFACE )
    {
        std::cout << tabs << "Failed to scan Audio Mute Interface." << std::endl;
        std::cout << tabs << result << std::endl;
    }

    IAudioPeakMeter *peakAudioMeter = nullptr;
    result = p_part->Activate( CLSCTX_ALL, __uuidof( IAudioPeakMeter ), reinterpret_cast< void ** >( &peakAudioMeter ) );
    if ( SUCCEEDED( result.GetResult() ) )
    {
        hasInterface = true;
        std::cout << tabs << "Peak Audio Peak Meter Interface" << std::endl;

        if ( verbose )
        {
            tabs.Inc();

            UINT peakMeterChannelCount = 0;
            result = peakAudioMeter->GetChannelCount( &peakMeterChannelCount );
            if ( SUCCEEDED( result.GetResult() ) )
            {
                std::cout << tabs << "Detected " << peakMeterChannelCount << " peak meter channels." << std::endl;
                tabs.Inc();

                for ( UINT peakChanelIdx = 0; peakChanelIdx < peakMeterChannelCount; ++peakChanelIdx )
                {
                    std::cout << tabs << "Channel " << peakChanelIdx + 1 << std::endl;
                    tabs.Inc();

                    float level = 0.0f;
                    result = peakAudioMeter->GetLevel( peakChanelIdx, &level );
                    if ( SUCCEEDED( result.GetResult() ) )
                    {
                        std::cout << tabs << "Level : " << level << std::endl;
                    }
                    else
                    {
                        std::cout << tabs << "Failed to obtain channel's peak level." << std::endl;
                        std::cout << tabs << result << std::endl;
                    }

                    tabs.Dec();
                }

                tabs.Dec();
            }
            else
            {
                std::cout << tabs << "Failed to obtain peak meter channel count" << std::endl;
                std::cout << tabs << result << std::endl;
            }

            tabs.Dec();
        }

        peakAudioMeter->Release();
    }
    else if ( result != E_NOINTERFACE )
    {
        std::cout << tabs << "Failed to scan Audio Peak Meter Interface." << std::endl;
        std::cout << tabs << result << std::endl;
    }

    IAudioVolumeLevel *volumeLevel = nullptr;
    result = p_part->Activate( CLSCTX_ALL, __uuidof( IAudioVolumeLevel ), reinterpret_cast< void ** >( &volumeLevel ) );
    if ( SUCCEEDED( result.GetResult() ) )
    {    
        hasInterface = true;
        std::cout << tabs << "Audio Volume Level Interface" << std::endl;

        if ( verbose )
        {
            tabs.Inc();

            UINT volumeLevelChannelCount = 0;
            result = volumeLevel->GetChannelCount( &volumeLevelChannelCount );
            if ( SUCCEEDED( result.GetResult() ) )
            {
                std::cout << tabs << "Detected " << volumeLevelChannelCount << " volume level channels." << std::endl;
                tabs.Inc();

                for ( UINT levelChannelIdx = 0; levelChannelIdx < volumeLevelChannelCount; ++levelChannelIdx )
                {
                    std::cout << tabs << "Channel " << levelChannelIdx + 1 << std::endl;
                    tabs.Inc();

                    float level = 0.0f;
                    result = volumeLevel->GetLevel( levelChannelIdx, &level );
                    if ( SUCCEEDED( result.GetResult() ) )
                    {
                        std::cout << tabs << "Level : " << level << " dB" << std::endl;
                    }
                    else
                    {
                        std::cout << tabs << "Failed to obtain channel volume level." << std::endl;
                        std::cout << tabs << result << std::endl;
                    }

                    float min   = 0.0f;
                    float max   = 0.0f;
                    float step  = 0.0f;
                    result = volumeLevel->GetLevelRange( levelChannelIdx, &min, &max, &step );
                    if ( SUCCEEDED( result.GetResult() ) )
                    {
                        std::cout << tabs << "Min   : " << min << " dB" << std::endl;
                        std::cout << tabs << "Max   : " << max << " dB" << std::endl;
                        std::cout << tabs << "Step  : " << step << " dB" << std::endl;
                    }
                    else
                    {
                        std::cout << tabs << "Failed to obtain channel volume level step information." << std::endl;
                        std::cout << tabs << result << std::endl;
                    }

                    tabs.Dec();
                }

                tabs.Dec();
            }
            else
            {
                std::cout << tabs << "Failed to obtain volume level channel count." << std::endl;
                std::cout << tabs << result << std::endl;
            }

            volumeLevel->Release();
            tabs.Dec();
        }
    }
    else if ( result != E_NOINTERFACE )
    {
        std::cout << tabs << "Failed to scan Audio Volume Level Interface." << std::endl;
        std::cout << tabs << result << std::endl;
    }

    IDeviceSpecificProperty *p_deviceSpecific = nullptr;
    result = p_part->Activate( CLSCTX_ALL, __uuidof( IDeviceSpecificProperty ), reinterpret_cast< void ** >( &p_deviceSpecific ) );
    if ( SUCCEEDED( result.GetResult() ) )
    {
        hasInterface = true;
        std::cout << tabs << "Device Specific Property Interface" << std::endl;

        if ( verbose )
        {
            tabs.Inc();

            LONG min;
            LONG max;
            LONG step;
            result = p_deviceSpecific->Get4BRange( &min, &max, &step );
            if ( SUCCEEDED( result.GetResult() ) )
            {
                std::cout << tabs << "Min   : " << min << std::endl;
                std::cout << tabs << "Max   : " << max << std::endl;
                std::cout << tabs << "Step  : " << step << std::endl;
            }
            else
            {
                std::cout << tabs << "Failed to obtain 4Byte range data" << std::endl;
                std::cout << tabs << result << std::endl;
            }

            VARTYPE type;
            result = p_deviceSpecific->GetType( &type );
            if ( SUCCEEDED( result.GetResult() ) )
            {
                std::cout << tabs << "Type is " << type << std::endl;

                DWORD dataSize = 0;
                char *data = nullptr;
                switch ( type )
                {
                    case VARENUM::VT_I2:
                        dataSize = 2;
                        break;
                    case VARENUM::VT_I4:
                        dataSize = 4;
                        break;
                    case VARENUM::VT_R4:
                        dataSize = 4;
                        break;
                    case VARENUM::VT_R8:
                        dataSize = 8;
                        break;
                    case VARENUM::VT_CY:
                        dataSize = sizeof( CURRENCY );
                        break;
                    case VARENUM::VT_DATE:
                        dataSize = sizeof( DATE );
                        break;
                    case VARENUM::VT_BSTR:
                        result = p_deviceSpecific->GetValue( NULL, &dataSize );
                        break;
                    case VARENUM::VT_DISPATCH:
                        dataSize = sizeof( IDispatch * );
                        break;
                    case VARENUM::VT_ERROR:
                        dataSize = sizeof( SCODE );
                        break;
                    case VARENUM::VT_BOOL:
                        dataSize = sizeof( BOOLEAN );
                        break;
                    case VARENUM::VT_VARIANT:
                        dataSize = sizeof( VARIANT * );
                        break;
                    case VARENUM::VT_UNKNOWN:
                        dataSize = sizeof( IUnknown * );
                        break;
                    case VARENUM::VT_DECIMAL:
                        dataSize = 16;
                        break;
                    case VARENUM::VT_RECORD:
                        result = p_deviceSpecific->GetValue( NULL, &dataSize );
                        break;
                    case VARENUM::VT_I1:
                        dataSize = sizeof( signed char );
                        break;
                    case VARENUM::VT_UI1:
                        dataSize = sizeof( unsigned char );
                        break;
                    case VARENUM::VT_UI2:
                        dataSize = sizeof( unsigned short );
                        break;
                    case VARENUM::VT_UI4:
                        dataSize = sizeof( ULONG );
                        break;
                    case VARENUM::VT_INT:
                        dataSize = sizeof( int );
                        break;
                    case VARENUM::VT_UINT:
                        dataSize = sizeof( unsigned int );
                        break;
                    case VARENUM::VT_ARRAY:
                        result = p_deviceSpecific->GetValue( NULL, &dataSize );
                        break;
                    case VARENUM::VT_BYREF:
                        result = p_deviceSpecific->GetValue( NULL, &dataSize );
                        break;

                    default:
                        result = S_FALSE;
                        break;
                }

                if ( SUCCEEDED( result.GetResult() ) )
                {
                    std::cout << tabs << "Custom data is " << dataSize << " bytes long." << std::endl;
                }
                else
                {
                    std::cout << tabs << "Failed to obtain a size for the custom data." << std::endl;
                    std::cout << tabs << result;
                }
            }
            else
            {
                std::cout << tabs << "Failed to obtain type data" << std::endl;
                std::cout << tabs << result << std::endl;
            }

            tabs.Dec();
        }

        p_deviceSpecific->Release();
    }
    else if ( result != E_NOINTERFACE )
    {
        std::cout << tabs << "Failed to scan Device Specific Property Interface." << std::endl;
        std::cout << tabs << result << std::endl;
    }

    IKsFormatSupport *formatSupported   = nullptr;
    result = p_part->Activate( CLSCTX_ALL, __uuidof( IKsFormatSupport ), reinterpret_cast< void ** >( &formatSupported ) );
    if ( SUCCEEDED( result.GetResult() ) )
    {
        hasInterface = true;
        std::cout << tabs << "Supported Format Interface" << std::endl;

        if ( verbose )
        {
            tabs.Inc();

            PKSDATAFORMAT dataFormat = nullptr;
            result = formatSupported->GetDevicePreferredFormat( &dataFormat );
            if ( SUCCEEDED( result.GetResult() ) )
            {
                std::cout << tabs << "Alignment         : " << dataFormat->Alignment   << std::endl;
                std::cout << tabs << "Flags             : " << dataFormat->Flags       << std::endl;
                std::cout << tabs << "KSDATAFORMAT size : " << dataFormat->FormatSize  << std::endl;
                std::cout << tabs << "Major Format GUID : " << dataFormat->MajorFormat << std::endl;
                std::cout << tabs << "Reserved          : " << dataFormat->Reserved    << std::endl;
                std::cout << tabs << "Sample Size       : " << dataFormat->SampleSize  << std::endl;
                std::cout << tabs << "Specifier GUID    : " << dataFormat->Specifier   << std::endl;
                std::cout << tabs << "Sub Format GUID   : " << dataFormat->SubFormat   << std::endl;
                std::cout << std::endl;

                if ( IsEqualGUID( KSDATAFORMAT_SPECIFIER_NONE, dataFormat->Specifier ) == TRUE )
                {
                    std::cout << tabs << "No specifier. Format does not support specifiers." << std::endl;
                }
                else if ( IsEqualGUID( KSDATAFORMAT_SPECIFIER_FILENAME, dataFormat->Specifier ) == TRUE )
                {
                    std::cout << tabs << "A null-terminated Unicode filename is present." << std::endl;
                }
                else if ( IsEqualGUID( KSDATAFORMAT_SPECIFIER_FILEHANDLE, dataFormat->Specifier ) == TRUE )
                {
                    std::cout << tabs << "A file handle is present." << std::endl;
                }

                if ( dataFormat->Flags & KSDATAFORMAT_ATTRIBUTES )
                {
                    std::cout << tabs << "Additional format data." << std::endl;
                    tabs.Inc();

                    char *data = reinterpret_cast< char * >( dataFormat );
                    data  += sizeof( KSDATAFORMAT );
                
                    PKSMULTIPLE_ITEM header = reinterpret_cast< PKSMULTIPLE_ITEM >( data );
                    std::cout << tabs << "Attributes Header" << std::endl;
                    tabs.Inc();

                    std::cout << tabs << "Header Size: " << header->Size << std::endl;
                    std::cout << tabs << "Held Attributers: " << header->Count << std::endl;

                    tabs.Dec();
                    std::cout << std::endl;

                    ULONG itemCount = header->Count;
                    data += header->Size;
                    for ( ULONG itemIdx = 0; itemIdx < itemCount; ++itemIdx )
                    {
                        std::cout << tabs << "Item Attribute " << itemIdx + 1 << std::endl;
                        tabs.Inc();

                        PKSATTRIBUTE item = reinterpret_cast< PKSATTRIBUTE >( data );

                        std::cout << tabs << "Attribute Size: " << item->Size << std::endl;
                        std::cout << tabs << "Attribute GUID: " << item->Attribute << std::endl;
                        std::cout << tabs << "Attribute is " << *( (item->Flags & KSATTRIBUTE_REQUIRED) ? "required" : "not required" ) << std::endl;

                        tabs.Dec();
                        data += item->Size;
                    }

                    tabs.Dec();
                }

                CoTaskMemFree( dataFormat );
            }
            else
            {
                std::cout << tabs << "Failed to obtain supported format information." << std::endl;
                std::cout << tabs << result << std::endl;
            }

            tabs.Dec();
        }

        formatSupported->Release();
    }
    else if ( result != E_NOINTERFACE )
    {
        std::cout << tabs << "Failed to scan Supported Format Interface." << std::endl;
        std::cout << tabs << result << std::endl;
    }

    IKsJackDescription *ksJackDesc  = nullptr;
    result = p_part->Activate( CLSCTX_ALL, __uuidof( IKsJackDescription ), reinterpret_cast< void ** >( &ksJackDesc ) );
    if ( SUCCEEDED( result.GetResult() ) )
    {
        hasInterface = true;
        std::cout << tabs << "Jack Description Interface" << std::endl;
            
        if ( verbose )
        {
            tabs.Inc();

            UINT jackCount = 0;
            result = ksJackDesc->GetJackCount( &jackCount );
            if ( SUCCEEDED( result.GetResult() ) )
            {
                std::cout << tabs << "Discoverd " << jackCount << " jacks." << std::endl;
                tabs.Inc();

                for ( UINT jackIdx = 0; jackIdx < jackCount; ++jackIdx )
                {
                    std::cout << tabs << "Jack " << jackIdx + 1 << std::endl;
                    tabs.Inc();

                    KSJACK_DESCRIPTION jackDesc;
                    std::memset( &jackDesc, 0, sizeof( jackDesc ) );

                    result = ksJackDesc->GetJackDescription( jackIdx, &jackDesc );
                    if ( SUCCEEDED( result.GetResult() ) )
                    {
                        std::cout << tabs << "Jack Status: "
                            << (jackDesc.IsConnected ? "Connected" : "Disconnected")
                            << std::endl;
                        tabs.Inc();

                        std::cout << tabs << "Note: device may appear connected, even if a system does not support jack-presence detection." << std::endl;
                        tabs.Dec();

                        std::cout << tabs << "Channel Mapping" << std::endl;

                        if ( jackDesc.ChannelMapping )
                        {
                            ScanChannelConfiguration( jackDesc.ChannelMapping );
                        }
                        else
                        {
                            std::cout << tabs << "Unkown Channel Configuration" << std::endl;
                        }
                        tabs.Dec();

                        std::cout << tabs << "Jack Color: ";
                        if ( jackDesc.Color )
                        {
                            std::cout << "{r, g, b}: {"
                                << ( ( jackDesc.Color & 0x00FF0000 ) >> 16 ) // red
                                << ", "
                                << ( ( jackDesc.Color & 0x0000FF00 ) >> 8 ) // green
                                << ", "
                                << ( ( jackDesc.Color & 0x000000FF ) >> 0 ) // blue
                                << "}";
                        }
                        else
                        {
                            std::cout << "Unknown, or unidentifiable.";
                        }
                        std::cout << std::endl;

                        std::cout << tabs << "Connection Type: ";
                        switch ( jackDesc.ConnectionType )
                        {
                            case EPcxConnectionType::eConnTypeUnknown:
                                std::cout << "Unknown";
                                break;
                            case EPcxConnectionType::eConnType3Point5mm:
                                std::cout << "1/8-inch jack";
                                break;
                            case EPcxConnectionType::eConnTypeQuarter:
                                std::cout << "1/4-inch jack";
                                break;
                            case EPcxConnectionType::eConnTypeAtapiInternal:
                                std::cout << "ATAPI internal connector";
                                break;
                            case EPcxConnectionType::eConnTypeRCA:
                                std::cout << "RCA jack";
                                break;
                            case EPcxConnectionType::eConnTypeOptical:
                                std::cout << "Optical connector";
                                break;
                            case EPcxConnectionType::eConnTypeOtherDigital:
                                std::cout << "Generic digital connector";
                                break;
                            case EPcxConnectionType::eConnTypeOtherAnalog:
                                std::cout << "Generic analog connector";
                                break;
                            case EPcxConnectionType::eConnTypeMultichannelAnalogDIN:
                                std::cout << "Multichannel analog DIN connector";
                                break;
                            case EPcxConnectionType::eConnTypeXlrProfessional:
                                std::cout << "XLR connector";
                                break;
                            case EPcxConnectionType::eConnTypeRJ11Modem:
                                std::cout << "RJ11 modem connector";
                                break;
                            case EPcxConnectionType::eConnTypeCombination:
                                std::cout << "Combination of connector types";
                                break;

                            default:
                                std::cout << "Failed to identify conctor type";
                                break;
                        }
                        std::cout << std::endl;

                        std::cout << tabs << "Jack General Location: ";
                        switch ( jackDesc.GenLocation )
                        {
                            case EPcxGenLocation::eGenLocPrimaryBox:
                                std::cout << "On primary chassis";
                                break;
                            case EPcxGenLocation::eGenLocInternal:
                                std::cout << "Inside primary chassis";
                                break;
                            case EPcxGenLocation::eGenLocSeparate:
                                std::cout << "On separate chassis";
                                break;
                            case EPcxGenLocation::eGenLocOther:
                                std::cout << "Other location";
                                break;

                            default:
                                std::cout << "Unknown";
                                break;
                        }
                        std::cout << std::endl;

                        std::cout << tabs << "Jack Specific Location: ";
                        switch ( jackDesc.GeoLocation )
                        {
                            case EPcxGeoLocation::eGeoLocRear:
                                std::cout << "Rear-mounted panel";
                                break;
                            case EPcxGeoLocation::eGeoLocFront:
                                std::cout << "Front-mounted panel";
                                break;
                            case EPcxGeoLocation::eGeoLocLeft:
                                std::cout << "Left-mounted panel";
                                break;
                            case EPcxGeoLocation::eGeoLocRight:
                                std::cout << "Right-mounted panel";
                                break;
                            case EPcxGeoLocation::eGeoLocTop:
                                std::cout << "Top-mounted pane";
                                break;
                            case EPcxGeoLocation::eGeoLocBottom:
                                std::cout << "Bottom-mounted panel";
                                break;
                            case EPcxGeoLocation::eGeoLocRearPanel:
                                std::cout << "Rear slide-open or pull-open panel";
                                break;
                            case EPcxGeoLocation::eGeoLocRiser:
                                std::cout << "Riser card";
                                break;
                            case EPcxGeoLocation::eGeoLocInsideMobileLid:
                                std::cout << "Inside lid of mobile computer";
                                break;
                            case EPcxGeoLocation::eGeoLocDrivebay:
                                std::cout << "Drive bay";
                                break;
                            case EPcxGeoLocation::eGeoLocHDMI:
                                std::cout << "HDMI connector";
                                break;
                            case EPcxGeoLocation::eGeoLocOutsideMobileLid:
                                std::cout << "Outside lid of mobile computer";
                                break;
                            case EPcxGeoLocation::eGeoLocATAPI:
                                std::cout << "ATAPI connector";
                                break;
                            case EPcxGeoLocation::eGeoLocNotApplicable:
                                std::cout << "Not Applicable";
                                break;

                            default:
                                std::cout << "Unknown";
                                break;
                        }
                        std::cout << std::endl;

                        std::cout << tabs << "Jack Port Connection Type : ";
                        switch ( jackDesc.PortConnection )
                        {
                            case EPxcPortConnection::ePortConnJack:
                                  std::cout << "Jack";
                                break;
                            case EPxcPortConnection::ePortConnIntegratedDevice:
                                std::cout << "Slot for an integrated device";
                                break;
                            case EPxcPortConnection::ePortConnBothIntegratedAndJack:
                                 std::cout << "Both a jack and a slot for an integrated device";
                                break;
                            case EPxcPortConnection::ePortConnUnknown:
                                 std::cout << "Unknown jack connection.";
                                break;

                            default:
                                std::cout << "Failed to identify the Port Conenction type.";
                                break;
                        }
                    }
                    else
                    {
                        std::cout << tabs << "Failed to obtain jack description." << std::endl;
                        std::cout << tabs << result << std::endl;
                    }
                    std::cout << std::endl;

                    tabs.Dec();
                }

                tabs.Dec();
            }
            else
            {
                std::cout << tabs << "Failed to obtain jack count." << std::endl;
                std::cout << tabs << result << std::endl;
            }

            tabs.Dec();
        }

        ksJackDesc->Release();
    }
    else if ( result != E_NOINTERFACE )
    {
        std::cout << tabs << "Failed to scan Jack Description Interface." << std::endl;
        std::cout << tabs << result << std::endl;
    }

    if ( hasInterface == false )
    {
        std::cout << tabs << "No part interfaces detected." << std::endl;
    }
}


static void ScanPartControlInterface( IPart *p_part )
{
    MyResult result = S_OK;
    Tabs tabs;

    UINT partControlInterfaceCount = 0;
    result = p_part->GetControlInterfaceCount( &partControlInterfaceCount );
    if ( SUCCEEDED( result.GetResult() ) )
    {
        std::cout << tabs << "Detected " << partControlInterfaceCount << " control interfaces on this part." << std::endl;

        if ( verbose )
        {
            tabs.Inc();

            for ( UINT controlInterfaceIdx = 0; controlInterfaceIdx < partControlInterfaceCount; ++controlInterfaceIdx )
            {
                std::cout << tabs << "Control Interface " << controlInterfaceIdx + 1 << std::endl;
                tabs.Inc();

                IControlInterface *p_partControlInterface = nullptr;
                result = p_part->GetControlInterface( controlInterfaceIdx, &p_partControlInterface );
                if ( SUCCEEDED( result.GetResult() ) )
                {
                    LPWSTR interfaceName = nullptr;
                    result = p_partControlInterface->GetName( &interfaceName );
                    if ( SUCCEEDED( result.GetResult() ) )
                    {
                        std::cout << tabs << "Control Interface Name: ";
                        if ( interfaceName && *interfaceName )
                        {
                            std::cout << interfaceName << std::endl;
                        }
                        else
                        {
                            std::cout << "Unknown" << std::endl;
                        }
                        CoTaskMemFree( interfaceName );
                    }
                    else
                    {
                        std::cout << tabs << "Failed to obtain the control interface name." << std::endl;
                        std::cout << tabs << result << std::endl;
                    }

                    GUID interfaceId;
                    result = p_partControlInterface->GetIID( &interfaceId );
                    if ( SUCCEEDED( result.GetResult() ) )
                    {
                        std::cout << tabs << "Device Interface ID: " << interfaceId << std::endl;
                    }
                    else
                    {
                        std::cout << tabs << "Failed to obtain the control interface ID." << std::endl;
                        std::cout << tabs << result << std::endl;
                    }
                }
                else
                {
                    std::cout << tabs << "Failed to obtain the current control interface." << std::endl;
                    std::cout << tabs << result << std::endl;
                }

                tabs.Dec();
            }

            tabs.Dec();
        }
    }
    else
    {
        std::cout << tabs << "Failed to obtain the current part." << std::endl;
        std::cout << tabs << result << std::endl;
    }
}


static void ScanDefaultAudioEndpoint( EDataFlow flowDir, ERole role, IMMDeviceEnumerator *p_deviceEnumerator )
{
    MyResult result = S_OK;
    IMMDevice *p_defaultEndpoint = nullptr;
    Tabs tabs;
    result = p_deviceEnumerator->GetDefaultAudioEndpoint( flowDir, role, &p_defaultEndpoint );
    if ( SUCCEEDED( result.GetResult() ) )
    {
        std::cout << tabs << "Detected" << std::endl;

        ScanDeviceName( p_defaultEndpoint );

        tabs.Inc();

        if ( displayInterfaces )
        {
            std::cout << tabs << "Scanning Device Interfaces" << std::endl << std::endl;
            ScanDeviceInterfaces( p_defaultEndpoint );
        }

        if ( displayTopology )
        {
            std::cout << tabs << "Traversing Device Topology" << std::endl << std::endl;
            BeginDeviceTopolgy( p_defaultEndpoint );
        }

        tabs.Dec();

        p_defaultEndpoint->Release();
    }
    else if ( result == E_NOTFOUND )
    {
        std::cout << tabs << "Not present" << std::endl;
    }
    else
    {
        std::cout << "Attempt to get device failed." << std::endl;
        std::cout << tabs << result << std::endl;
    }
}


static void ScanChannelConfiguration( DWORD config )
{
    Tabs tabs;
    tabs.Inc();

    if ( config & SPEAKER_FRONT_LEFT )
    {
        std::cout << tabs << "Front Left" << std::endl;
    }
    if ( config & SPEAKER_FRONT_RIGHT )
    {
        std::cout << tabs << "Front Right" << std::endl;
    }
    if ( config & SPEAKER_FRONT_CENTER )
    {
        std::cout << tabs << "Front Center" << std::endl;
    }
    if ( config & SPEAKER_LOW_FREQUENCY )
    {
        std::cout << tabs << "Low Frequency" << std::endl;
    }
    if ( config & SPEAKER_BACK_LEFT )
    {
        std::cout << tabs << "Back Left" << std::endl;
    }
    if ( config & SPEAKER_BACK_RIGHT )
    {
        std::cout << tabs << "Back Right" << std::endl;
    }
    if ( config & SPEAKER_FRONT_LEFT_OF_CENTER )
    {
        std::cout << tabs << "Front Left of Center" << std::endl;
    }
    if ( config & SPEAKER_FRONT_RIGHT_OF_CENTER )
    {
        std::cout << tabs << "Front Right of Center" << std::endl;
    }
    if ( config & SPEAKER_BACK_CENTER )
    {
        std::cout << tabs << "Back Center" << std::endl;
    }
    if ( config & SPEAKER_SIDE_LEFT )
    {
        std::cout << tabs << "Side Left" << std::endl;
    }
    if ( config & SPEAKER_SIDE_RIGHT )
    {
        std::cout << tabs << "Side Right" << std::endl;
    }
    if ( config & SPEAKER_TOP_CENTER )
    {
        std::cout << tabs << "Top Center" << std::endl;
    }
    if ( config & SPEAKER_TOP_FRONT_LEFT )
    {
        std::cout << tabs << "Top Front Left" << std::endl;
    }
    if ( config & SPEAKER_TOP_FRONT_CENTER )
    {
        std::cout << tabs << "Top Front Center" << std::endl;
    }
    if ( config & SPEAKER_TOP_FRONT_RIGHT )
    {
        std::cout << tabs << "Top Front Right" << std::endl;
    }
    if ( config & SPEAKER_TOP_BACK_LEFT )
    {
        std::cout << tabs << "Top Back Left" << std::endl;
    }
    if ( config & SPEAKER_TOP_BACK_CENTER )
    {
        std::cout << tabs << "Top Back Center" << std::endl;
    }
    if ( config & SPEAKER_TOP_BACK_RIGHT )
    {
        std::cout << tabs << "Top Back Right" << std::endl;
    }

    tabs.Dec();
}


static void ScanPartType_NoTab( DWORD type )
{
    if ( type & VT_I1 )
    {
        std::cout << "1-byte signed integer";
    }
    if ( type & VT_UI1 )
    {
        std::cout << "1-byte unsigned integer";
    }
    if ( type & VT_I2 )
    {
        std::cout << "Two bytes representing a 2-byte signed integer value";
    }
    if ( type & VT_UI2 )
    {
        std::cout << "2-byte unsigned integer";
    }
    if ( type & VT_I4 )
    {
        std::cout << "4-byte signed integer value";
    }
    if ( type & VT_UI4 )
    {
        std::cout << "4-byte unsigned integer";
    }
    if ( type & VT_INT )
    {
        std::cout << "4-byte signed integer value (equivalent to VT_I4)";
    }
    if ( type & VT_UINT )
    {
        std::cout << "4-byte unsigned integer (equivalent to VT_UI4)";
    }
    if ( type & VT_R4 )
    {
        std::cout << "32-bit IEEE floating point value";
    }
    if ( type & VT_R8 )
    {
        std::cout << "64-bit IEEE floating point value";
    }
    if ( type & VT_BOOL )
    {
        std::cout << "Boolean value, a WORD that contains 0 (FALSE) or -1 (TRUE)";
    }
    if ( type & VT_DECIMAL )
    {
        std::cout << "A DECIMAL structure";
    }
    if ( type & VT_ERROR )
    {
        std::cout << "A DWORD that contains a status code";
    }
    if ( type & VT_CY )
    {
        std::cout << "8-byte two's complement integer (scaled by 10,000). This type is commonly used for currency amounts";
    }
    if ( type & VT_DATE )
    {
        std::cout << "A 64-bit floating point number representing the number of days (not seconds) since December 31, 1899";
    }
    if ( type & VT_FILETIME )
    {
        std::cout << "64-bit FILETIME structure as defined by Win32";
    }
    if ( type & VT_CLSID )
    {
        std::cout << "Pointer to a class identifier (CLSID) (or other globally unique identifier (GUID))";
    }
    if ( type & VT_CF )
    {
        std::cout << "Pointer to a CLIPDATA structure";
    }
    if ( type & VT_BSTR )
    {
        std::cout << "Pointer to a null-terminated Unicode string";
    }
    if ( type & VT_UNKNOWN )
    {
        std::cout << "Unkown type";
    }
    if ( type & VT_DISPATCH )
    {
        std::cout << "VT_DISPATCH";
    }
    if ( type & VT_ARRAY )
    {
        std::cout << "Arrayy";
    }
    if ( type & VT_LPSTR )
    {
        std::cout << "A pointer to a null-terminated ANSI string in the system default code page";
    }
    if ( type & VT_LPWSTR )
    {
        std::cout << "A pointer to a null-terminated Unicode string in the user default locale";
    }
    if ( type & VT_VARIANT )
    {
        std::cout << "A DWORD type indicator followed by the corresponding value";
    }
}


static void _FreeMediaType( AM_MEDIA_TYPE &mt )
{
    if ( mt.cbFormat != 0 )
    {
        CoTaskMemFree( reinterpret_cast< PVOID >( mt.pbFormat ) );
        mt.cbFormat = 0;
        mt.pbFormat = nullptr;
    }
    if ( mt.pUnk != nullptr )
    {
        mt.pUnk->Release();
        mt.pUnk = nullptr;
    }
}


static void _DeleteMediaType( AM_MEDIA_TYPE *pmt )
{
    if ( pmt != nullptr )
    {
        _FreeMediaType( *pmt ); 
        CoTaskMemFree( pmt );
    }
}
