/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#include <memory.h> /* for memset */
#include "vxi11core.h"

/* Default timeout can be changed using clnt_control() */
static struct timeval TIMEOUT = { 25, 0 };

enum clnt_stat 
device_abort_1(Device_Link *argp, Device_Error *clnt_res, CLIENT *clnt)
{
	return (clnt_call(clnt, device_abort,
		(xdrproc_t) xdr_Device_Link, (caddr_t) argp,
		(xdrproc_t) xdr_Device_Error, (caddr_t) clnt_res,
		TIMEOUT));
}

enum clnt_stat 
create_link_1(Create_LinkParms *argp, Create_LinkResp *clnt_res, CLIENT *clnt)
{
	return (clnt_call(clnt, create_link,
		(xdrproc_t) xdr_Create_LinkParms, (caddr_t) argp,
		(xdrproc_t) xdr_Create_LinkResp, (caddr_t) clnt_res,
		TIMEOUT));
}

enum clnt_stat 
device_write_1(Device_WriteParms *argp, Device_WriteResp *clnt_res, CLIENT *clnt)
{
	return (clnt_call(clnt, device_write,
		(xdrproc_t) xdr_Device_WriteParms, (caddr_t) argp,
		(xdrproc_t) xdr_Device_WriteResp, (caddr_t) clnt_res,
		TIMEOUT));
}

enum clnt_stat 
device_read_1(Device_ReadParms *argp, Device_ReadResp *clnt_res, CLIENT *clnt)
{
	return (clnt_call(clnt, device_read,
		(xdrproc_t) xdr_Device_ReadParms, (caddr_t) argp,
		(xdrproc_t) xdr_Device_ReadResp, (caddr_t) clnt_res,
		TIMEOUT));
}

enum clnt_stat 
device_readstb_1(Device_GenericParms *argp, Device_ReadStbResp *clnt_res, CLIENT *clnt)
{
	return (clnt_call(clnt, device_readstb,
		(xdrproc_t) xdr_Device_GenericParms, (caddr_t) argp,
		(xdrproc_t) xdr_Device_ReadStbResp, (caddr_t) clnt_res,
		TIMEOUT));
}

enum clnt_stat 
device_trigger_1(Device_GenericParms *argp, Device_Error *clnt_res, CLIENT *clnt)
{
	return (clnt_call(clnt, device_trigger,
		(xdrproc_t) xdr_Device_GenericParms, (caddr_t) argp,
		(xdrproc_t) xdr_Device_Error, (caddr_t) clnt_res,
		TIMEOUT));
}

enum clnt_stat 
device_clear_1(Device_GenericParms *argp, Device_Error *clnt_res, CLIENT *clnt)
{
	return (clnt_call(clnt, device_clear,
		(xdrproc_t) xdr_Device_GenericParms, (caddr_t) argp,
		(xdrproc_t) xdr_Device_Error, (caddr_t) clnt_res,
		TIMEOUT));
}

enum clnt_stat 
device_remote_1(Device_GenericParms *argp, Device_Error *clnt_res, CLIENT *clnt)
{
	return (clnt_call(clnt, device_remote,
		(xdrproc_t) xdr_Device_GenericParms, (caddr_t) argp,
		(xdrproc_t) xdr_Device_Error, (caddr_t) clnt_res,
		TIMEOUT));
}

enum clnt_stat 
device_local_1(Device_GenericParms *argp, Device_Error *clnt_res, CLIENT *clnt)
{
	return (clnt_call(clnt, device_local,
		(xdrproc_t) xdr_Device_GenericParms, (caddr_t) argp,
		(xdrproc_t) xdr_Device_Error, (caddr_t) clnt_res,
		TIMEOUT));
}

enum clnt_stat 
device_lock_1(Device_LockParms *argp, Device_Error *clnt_res, CLIENT *clnt)
{
	return (clnt_call(clnt, device_lock,
		(xdrproc_t) xdr_Device_LockParms, (caddr_t) argp,
		(xdrproc_t) xdr_Device_Error, (caddr_t) clnt_res,
		TIMEOUT));
}

enum clnt_stat 
device_unlock_1(Device_Link *argp, Device_Error *clnt_res, CLIENT *clnt)
{
	return (clnt_call(clnt, device_unlock,
		(xdrproc_t) xdr_Device_Link, (caddr_t) argp,
		(xdrproc_t) xdr_Device_Error, (caddr_t) clnt_res,
		TIMEOUT));
}

enum clnt_stat 
device_enable_srq_1(Device_EnableSrqParms *argp, Device_Error *clnt_res, CLIENT *clnt)
{
	return (clnt_call(clnt, device_enable_srq,
		(xdrproc_t) xdr_Device_EnableSrqParms, (caddr_t) argp,
		(xdrproc_t) xdr_Device_Error, (caddr_t) clnt_res,
		TIMEOUT));
}

enum clnt_stat 
device_docmd_1(Device_DocmdParms *argp, Device_DocmdResp *clnt_res, CLIENT *clnt)
{
	return (clnt_call(clnt, device_docmd,
		(xdrproc_t) xdr_Device_DocmdParms, (caddr_t) argp,
		(xdrproc_t) xdr_Device_DocmdResp, (caddr_t) clnt_res,
		TIMEOUT));
}

enum clnt_stat 
destroy_link_1(Device_Link *argp, Device_Error *clnt_res, CLIENT *clnt)
{
	return (clnt_call(clnt, destroy_link,
		(xdrproc_t) xdr_Device_Link, (caddr_t) argp,
		(xdrproc_t) xdr_Device_Error, (caddr_t) clnt_res,
		TIMEOUT));
}

enum clnt_stat 
create_intr_chan_1(Device_RemoteFunc *argp, Device_Error *clnt_res, CLIENT *clnt)
{
	return (clnt_call(clnt, create_intr_chan,
		(xdrproc_t) xdr_Device_RemoteFunc, (caddr_t) argp,
		(xdrproc_t) xdr_Device_Error, (caddr_t) clnt_res,
		TIMEOUT));
}

enum clnt_stat 
destroy_intr_chan_1(void *argp, Device_Error *clnt_res, CLIENT *clnt)
{
	return (clnt_call(clnt, destroy_intr_chan,
		(xdrproc_t) xdr_void, (caddr_t) argp,
		(xdrproc_t) xdr_Device_Error, (caddr_t) clnt_res,
		TIMEOUT));
}
