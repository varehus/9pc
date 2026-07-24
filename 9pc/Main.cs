/*
 * Copy me if you can.
 * by 20h
 */

using System;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace ninepc
{
	public enum proto : uint {
		Blocksize = 		65536,
		
		Tversion =		100,
		Rversion,
		Tauth,
		Rauth,
		Tattach,
		Rattach,
		Terror,
		Rerror,
		Tflush,
		Rflush,
		Twalk,
		Rwalk,
		Topen,
		Ropen,
		Tcreate,
		Rcreate,
		Tread,
		Rread,
		Twrite,
		Rwrite,
		Tclunk,
		Rclunk,
		Tremove,
		Rremove,
		Tstat,
		Rstat,
		Twstat,
		Rwstat,

		BIT64SZ =		8,
		BIT32SZ =		4,
		BIT16SZ =		2,
		BIT8SZ =			1,
		QIDSZ =			(BIT8SZ + BIT32SZ + BIT64SZ),
		
		MAXWELEM =		16,
		STATFIXLEN =		(BIT16SZ + QIDSZ + 5 * BIT16SZ + 4 * BIT32SZ + BIT64SZ),
		MAXPKTSIZE =		8192,
		IOHDRSIZE =			(BIT8SZ + BIT16SZ + 3 * BIT32SZ + BIT64SZ),
		
		DMDIR = 			0x80000000,
		DMAPPEND = 	0x40000000,
		DMEXCL =			0x20000000,
		DMMOUNT =		0x10000000,
		DMAUTH =			0x08000000,
		DMTMP =			0x04000000,
		DMNONE =			0xFC000000,
	}

	struct Qid {
		public ulong path;
		public uint vers;
		public byte type;
	}
	
	struct Dir {
		public int status;
	
		public ushort type;
		public uint dev;

		public Qid qid;
		public uint mode;
		public uint atime;
		public uint mtime;
		public ulong length;
		public string name;
		public string uid;
		public string gid;
		public string muid;
	}

	struct Fcall {
		public int status;
	
		public byte type;
		public int fid;
		public ushort tag;

		public uint msize;
		public string version;

		public ushort oldtag;

		public string ename;

		public Qid qid;
		public uint iounit;

		public Qid aqid;

		public int afid;
		public string uname;
		public string aname;

		public uint perm;
		public string name;
		public byte mode;

		public int newfid;
		public ushort nwname;
		public string[] wname;

		public ushort nwqid;
		public Qid[] wqid;

		public ulong offset;
		public uint count;
		public Byte[] data;

		public ushort nstat;
		public Byte[] stat;
	}
	
	class ninepexception : Exception
	{
		public ninepexception(string str)
		{
			Console.WriteLine("9P error: {0}", str);
		}
	}
	
	class ninep
	{
		Socket sock;
		public Fcall fin;
		public Fcall fout;
		
		public Dir dir;

		public Byte[] pktin;
		public Byte[] pktout;
		
		public Byte[] readbuf;
		
		public ushort tag;
		public int root;
		public int afid;
		public int cwd;
		public int fid;
		public int ffid;
		
		public string uname;
		public string aname;
		
		public uint mmsgsz;
		public uint mdatasz;

		public string modestr(uint mode)
		{
			string[] bits;
			string d;
			
			bits = new string[8] {"---", "--x", "-w-", "-wx", "r--", "r-x", "rw-", "rwx"};
			d = "";
			if((mode & (uint)proto.DMDIR) > 0)
				d += "d";
			if((mode & (uint)proto.DMAPPEND) > 0)
				d += "a";
			if((mode & (uint)proto.DMEXCL) > 0)
				d += "e";
			if((mode & (uint)proto.DMMOUNT) > 0)
				d += "m";
			if((mode & (uint)proto.DMAUTH) > 0)
				d += "u";
			if((mode & (uint)proto.DMTMP) > 0)
				d += "t";
			if((mode & (uint)proto.DMNONE) == 0)
				d = "-";

			return string.Format(null, "{0}{1}{2}{3}", new Object[] {d, bits[(mode >> 6) & 0x07],
								bits[(mode >> 3) & 0x07], bits[mode & 0x07]});
		}

		public void connect(string host, int port)
		{
			IPHostEntry iphost;
			IPAddress[] addr;
			EndPoint ep;

			tag = 10;
			root = 9;
			afid = -1;
			cwd = 7;
			fid = 6;
			ffid = 5;
			mmsgsz = (uint)proto.MAXPKTSIZE;
			mdatasz = mmsgsz - (uint)proto.IOHDRSIZE;
			
			uname = "andrey";
			aname = "";
			
			fin = new Fcall();
			pktin = new Byte[mmsgsz];
			
			iphost = Dns.Resolve(host);
			addr = iphost.AddressList;
			ep = new IPEndPoint(addr[0], port);
			
			sock = new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp);
			try {
				sock.Connect(ep);
				Console.WriteLine("Connected");
			} catch(Exception ex) {
				throw new ninepexception(ex.ToString());
			}
		}
		
		public void shutdown()
		{
			sock.Shutdown(SocketShutdown.Both);
			sock.Close();
			Console.WriteLine("Disconnected");
		}

		public ulong getulong(Byte[] data, uint dp)
		{
			return BitConverter.ToUInt64(data, (int)dp);
		}
		
		public uint getuint(Byte[] data, uint dp)
		{
			return BitConverter.ToUInt32(data, (int)dp);
		}
		
		public ushort getushort(Byte[] data, uint dp)
		{
			return BitConverter.ToUInt16(data, (int)dp);
		}
		
		public string getstring(Byte[] data, uint dp)
		{
			ushort len;
			char[] strdata;
			string ret;
        	UTF8Encoding utf8;
        	
        	utf8 = new UTF8Encoding();
			
			len = getushort(data, dp);
			dp += (uint)proto.BIT16SZ;
			
			strdata = new char[utf8.GetCharCount(data, (int)dp, (int)len)];
			utf8.GetChars(data, (int)dp, (int)len, strdata, 0);
			ret = new string(strdata);
			
			return ret;
		}
		
		public string convstring(Byte[] data)
		{
			char[] strdata;
			string ret;
        	UTF8Encoding utf8;
        	
        	utf8 = new UTF8Encoding();
			
			strdata = new char[utf8.GetCharCount(data, 0, data.Length)];
			utf8.GetChars(data, 0, data.Length, strdata, 0);
			ret = new string(strdata);
			
			return ret;
		}

		public Qid getqid(Byte[] data, uint dp)
		{
			Qid q;
			
			q.type = data[dp];
			dp += (uint)proto.BIT8SZ;
			q.vers = getuint(data, dp);
			dp += (uint)proto.BIT32SZ;
			q.path = getulong(data, dp);
			dp += (uint)proto.BIT64SZ;
			
			return q;
		}
		
		public void putulong(Byte[] data, uint dp, ulong var)
		{
			Byte[] datavar;
			
			datavar = BitConverter.GetBytes(var);
			Array.Copy(datavar, 0, data, dp, (uint)datavar.Length);
		}
		
		public void putuint(Byte[] data, uint dp, uint var)
		{
			Byte[] datavar;
			
			datavar = BitConverter.GetBytes(var);
			Array.Copy(datavar, 0, data, dp, (uint)datavar.Length);
		}
		
		public void putushort(Byte[] data, uint dp, ushort var)
		{
			Byte[] datavar;
			
			datavar = BitConverter.GetBytes(var);
			Array.Copy(datavar, 0, data, dp, (uint)datavar.Length);
		}
		
		public void putstring(Byte[] data, uint dp, string var)
		{
			Byte[] strdata;
        	UTF8Encoding utf8;
        	
        	utf8 = new UTF8Encoding();
			
			putushort(data, dp, (ushort)var.Length);
			dp += (uint)proto.BIT16SZ;
			
			strdata = utf8.GetBytes(var);
			Array.Copy(strdata, 0, data, dp, (uint)strdata.Length);
		}			

		public void putqid(Byte[] data, uint dp, Qid q)
		{
			data[dp] = q.type;
			dp += (uint)proto.BIT8SZ;
			putuint(data, dp, q.vers);
			dp += (uint)proto.BIT32SZ;
			putulong(data, dp, q.path);
			dp += (uint)proto.BIT64SZ;
		}

		public Byte[] recvn(int n)
		{
			Byte[] data;
			int r, i;

			r = 0;
			data = new Byte[n];

			while(r < n) {
				i = sock.Receive(data, r, data.Length - r, SocketFlags.None);
				r += i;
				if(i == 0)
					break;
			}
			
			return data;
		}

		public Byte[] read9pmsg()
		{
			Byte[] data, len, pkt;
			uint pktlen;

			len = recvn((int)proto.BIT32SZ);
			pktlen = getuint(len, 0);
			if(pktlen - (int)proto.BIT32SZ > mmsgsz)
				throw new ninepexception("pkt too small");

			data = recvn((int)pktlen - (int)proto.BIT32SZ);

			pkt = new Byte[pktlen];
			len.CopyTo(pkt, 0);
			data.CopyTo(pkt, (int)proto.BIT32SZ);
			
			return pkt;
		}
		
		public void send9pmsg(Byte[] pkt)
		{
			int len;

			len = (int)getuint(pkt, 0);
			
			try {
				sock.Send(pkt, len, SocketFlags.None);
			} catch(Exception ex) {
				Console.WriteLine("Error send9pmsg: {0}", ex.ToString());
				throw new ninepexception("send9pmsg failed");
			}
		}
		
		public Fcall convM2S(Byte[] pkt)
		{
			Byte[] buf;
			uint len, pp, i;
			Fcall f;

			f = new Fcall();
			buf = new Byte[(int)proto.BIT32SZ];
			pp = 0;

			if(pkt.Length < (int)proto.BIT32SZ + (int)proto.BIT8SZ + (int)proto.BIT16SZ)
				return f;
			len = getuint(pkt, 0);
			if(len < (int)proto.BIT32SZ + (int)proto.BIT8SZ + (int)proto.BIT16SZ)
				return f;
			pp += (uint)proto.BIT32SZ;

			f.type = pkt[pp];
			pp += (uint)proto.BIT8SZ;
			Array.Copy(pkt, pp, buf, (uint)proto.BIT32SZ - (uint)proto.BIT16SZ, (uint)proto.BIT16SZ);  
			f.tag = getushort(pkt, pp);
			pp += (uint)proto.BIT16SZ;
			
			switch(f.type) {
			default:
				return f;
			case (byte)proto.Tversion:
				if(pp + (uint)proto.BIT32SZ > len)
					return f;
				Array.Copy(pkt, pp, buf, (uint)proto.BIT32SZ - (uint)proto.BIT16SZ, (uint)proto.BIT16SZ);
				f.msize = getuint(pkt, pp);
				pp += (uint)proto.BIT32SZ;
				f.version = getstring(pkt, pp);
				pp += (uint)f.version.Length;
				break;
			case (byte)proto.Tflush:
				if(pp + (uint)proto.BIT16SZ > len)
					return f;
				f.oldtag = getushort(pkt, pp);
				pp += (uint)proto.BIT16SZ;
				break;
			case (byte)proto.Tauth:
				if(pp + (uint)proto.BIT32SZ > len)
					return f;
				f.afid = (int)getuint(pkt, pp);
				pp += (uint)proto.BIT32SZ;
				f.uname = getstring(pkt, pp);
				pp += (uint)f.uname.Length;
				f.aname = getstring(pkt, pp);
				pp += (uint)f.aname.Length;
				break;
			case (byte)proto.Tattach:
				if(pp + (uint)proto.BIT32SZ + (uint)proto.BIT32SZ > len)
					return f;
				f.fid = (int)getuint(pkt, pp);
				pp += (uint)proto.BIT32SZ;
				f.afid = (int)getuint(pkt, pp);
				pp += (uint)proto.BIT32SZ;
				f.uname = getstring(pkt, pp);
				pp += (uint)f.uname.Length;
				f.aname = getstring(pkt, pp);
				pp += (uint)f.aname.Length;
				break;
			case (byte)proto.Twalk:
				if(pp + (uint)proto.BIT32SZ + (uint)proto.BIT32SZ + (uint)proto.BIT16SZ > len)
					return f;
				f.fid = (int)getuint(pkt, pp);
				pp += (uint)proto.BIT32SZ;
				f.newfid = (int)getuint(pkt, pp);
				pp += (uint)proto.BIT32SZ;
				f.nwname = getushort(pkt, pp);
				if(f.nwname > (int)proto.MAXWELEM)
					return f;
				f.wname = new string[f.nwname];
				for(i = 0; i < f.nwname; i++) {
					f.wname[i] = getstring(pkt, pp);
					pp += (uint)f.wname[i].Length;
				}
				break;
			case (byte)proto.Topen:
				if(pp + (uint)proto.BIT32SZ + (uint)proto.BIT8SZ > len)
					return f;
				f.fid = (int)getuint(pkt, pp);
				pp += (uint)proto.BIT32SZ;
				f.mode = pkt[pp];
				pp += (uint)proto.BIT8SZ;
				break;
			case (byte)proto.Tcreate:
				if(pp + (uint)proto.BIT32SZ > len)
					return f;
				f.fid = (int)getuint(pkt, pp);
				pp += (uint)proto.BIT32SZ;
				f.name = getstring(pkt, pp);
				pp += (uint)f.name.Length;
				if(pp + (uint)proto.BIT32SZ + (uint)proto.BIT8SZ > len)
					return f;
				f.perm = getuint(pkt, pp);
				pp += (uint)proto.BIT32SZ;
				f.mode = pkt[pp];
				pp += (uint)proto.BIT8SZ;
				break;
			case (byte)proto.Tread:
				if(pp + (uint)proto.BIT32SZ + (uint)proto.BIT64SZ + (uint)proto.BIT32SZ > len)
					return f;
				f.fid = (int)getuint(pkt, pp);
				pp += (uint)proto.BIT32SZ;
				f.offset = getulong(pkt, pp);
				pp += (uint)proto.BIT64SZ;
				f.count = getuint(pkt, pp);
				pp += (uint)proto.BIT32SZ;
				break;
			case (byte)proto.Twrite:
				if(pp + (uint)proto.BIT32SZ + (uint)proto.BIT64SZ + (uint)proto.BIT32SZ > len)
					return f;
				f.fid = (int)getuint(pkt, pp);
				pp += (uint)proto.BIT32SZ;
				f.offset = getulong(pkt, pp);
				pp += (uint)proto.BIT64SZ;
				f.count = getuint(pkt, pp);
				pp += (uint)proto.BIT32SZ;
				if(pp + f.count > len)
					return f;
				f.data = new Byte[f.count];
				Array.Copy(pkt, pp, f.data, 0, f.count);
				pp += f.count;
				break;
			case (byte)proto.Tclunk:
			case (byte)proto.Tremove:
			case (byte)proto.Tstat:
				if(pp + (uint)proto.BIT32SZ > len)
					return f;
				f.fid = (int)getuint(pkt, pp);
				pp += (uint)proto.BIT32SZ;
				break;
			case (byte)proto.Twstat:
				if(pp + (uint)proto.BIT32SZ + (uint)proto.BIT16SZ > len)
					return f;
				f.fid = (int)getuint(pkt, pp);
				pp += (uint)proto.BIT32SZ;
				f.nstat = getushort(pkt, pp);
				pp += (uint)proto.BIT16SZ;
				if(pp + f.nstat > len)
					return f;
				f.stat = new Byte[f.nstat];
				Array.Copy(pkt, pp, f.stat, 0, f.nstat);
				pp += f.nstat;
				break;
				
			case (byte)proto.Rversion:
				if(pp + (uint)proto.BIT32SZ > len)
					return f;
				f.msize = getuint(pkt, pp);
				pp += (uint)proto.BIT32SZ;
				f.version = getstring(pkt, pp);
				pp += (uint)f.version.Length;
				break;
			case (byte)proto.Rerror:
				f.ename = getstring(pkt, pp);
				pp += (uint)f.ename.Length;
				break;
			case (byte)proto.Rauth:
				f.aqid = getqid(pkt, pp);
				pp += (uint)proto.QIDSZ;
				break;
			case (byte)proto.Rattach:
				f.qid = getqid(pkt, pp);
				pp += (uint)proto.QIDSZ;
				break;
			case (byte)proto.Rwalk:
				if(pp + (uint)proto.BIT16SZ > len)
					return f;
				f.nwqid = getushort(pkt, pp);
				pp += (uint)proto.BIT16SZ;
				if(f.nwqid > (int)proto.MAXWELEM)
					return f;
				f.wqid = new Qid[f.nwqid];
				for(i = 0; i < f.nwqid; i++) {
					f.wqid[i] = getqid(pkt, pp);
					pp += (uint)proto.QIDSZ;
				}
				break;
			case (byte)proto.Ropen:
			case (byte)proto.Rcreate:
				f.qid = getqid(pkt, pp);
				pp += (uint)proto.QIDSZ;
				if(pp + (uint)proto.BIT32SZ > len)
					return f;
				f.iounit = getuint(pkt, pp);
				pp += (uint)proto.BIT32SZ;
				break;
			case (byte)proto.Rread:
				if(pp + (uint)proto.BIT32SZ > len)
					return f;
				f.count = getuint(pkt, pp);
				pp += (uint)proto.BIT32SZ;
				if(pp + f.count > len)
					return f;
				f.data = new Byte[f.count];
				Array.Copy(pkt, pp, f.data, 0, f.count);
				pp += f.count;
				break;
			case (byte)proto.Rwrite:
				if(pp + (uint)proto.BIT32SZ > len)
					return f;
				f.count = getuint(pkt, pp);
				pp += (uint)proto.BIT32SZ;
				break;
			case (byte)proto.Rclunk:
			case (byte)proto.Rremove:
			case (byte)proto.Rwstat:
			case (byte)proto.Rflush:
				break;
			case (byte)proto.Rstat:
				if(pp + (uint)proto.BIT16SZ > len)
					return f;
				f.nstat = getushort(pkt, pp);
				pp += (uint)proto.BIT16SZ;
				if(pp + f.nstat > len)
					return f;
				f.stat = new Byte[f.nstat];
				Array.Copy(pkt, pp, f.stat, 0, f.nstat);
				pp += (uint)f.nstat;
				break;
			}
			
			if(pp <= len)
				f.status = 1;
				
			return f;
		}

		public uint sizeS2M(Fcall f)
		{
			uint n, i;
			
			n = (uint)proto.BIT32SZ + (uint)proto.BIT8SZ + (uint)proto.BIT16SZ;
			switch(f.type) {
			default:
				return 0;
			case (byte)proto.Tversion:
			case (byte)proto.Rversion:
				n += (uint)proto.BIT32SZ + (uint)proto.BIT16SZ + (uint)f.version.Length;
				break;
			case (byte)proto.Tflush:
				n += (uint)proto.BIT16SZ;
				break;
			case (byte)proto.Tauth:
				n += (uint)proto.BIT32SZ + 2 * (uint)proto.BIT16SZ + (uint)f.uname.Length + (uint)f.aname.Length;
				break;
			case (byte)proto.Tattach:
				n += 2 * (uint)proto.BIT32SZ + 2 * (uint)proto.BIT16SZ + (uint)f.uname.Length + (uint)f.aname.Length;
				break;
			case (byte)proto.Twalk:
				n += 2 * (uint)proto.BIT32SZ + (uint)proto.BIT16SZ;
				for(i = 0; i < f.nwname; i++)
					n += (uint)f.wname[i].Length + (uint)proto.BIT16SZ;
				break;
			case (byte)proto.Topen:
				n += (uint)proto.BIT32SZ + (uint)proto.BIT8SZ;
				break;
			case (byte)proto.Tcreate:
				n += 2 * (uint)proto.BIT32SZ + (uint)proto.BIT8SZ + (uint)proto.BIT16SZ + (uint)f.name.Length;
				break;
			case (byte)proto.Twrite:
				n += 2 * (uint)proto.BIT32SZ + (uint)proto.BIT64SZ + f.count;
				break;
			case (byte)proto.Tread:
				n += 2 * (uint)proto.BIT32SZ + (uint)proto.BIT64SZ;
				break;
			case (byte)proto.Tclunk:
			case (byte)proto.Tremove:
			case (byte)proto.Tstat:
			case (byte)proto.Rwrite:
				n += (uint)proto.BIT32SZ;
				break;
			case (byte)proto.Twstat:
				n += (uint)proto.BIT32SZ + 2 * (uint)proto.BIT16SZ + f.nstat;
				break;

			case (byte)proto.Rerror:
				n += (uint)proto.BIT16SZ + (uint)f.ename.Length;
				break;
			case (byte)proto.Rflush:
			case (byte)proto.Rclunk:
			case (byte)proto.Rremove:
			case (byte)proto.Rwstat:
				break;
			case (byte)proto.Rauth:
			case (byte)proto.Rattach:
				n += (uint)proto.QIDSZ;
				break;
			case (byte)proto.Rwalk:
				n += (uint)proto.BIT16SZ + f.nwqid * (uint)proto.QIDSZ;
				break;
			case (byte)proto.Ropen:
			case (byte)proto.Rcreate:
				n += (uint)proto.QIDSZ + (uint)proto.BIT32SZ;
				break;
			case (byte)proto.Rread:
				n += (uint)proto.BIT32SZ + f.count;
				break;
			case (byte)proto.Rstat:
				n += (uint)proto.BIT16SZ + f.nstat;
				break;
			}
			
			return n;
		}

		public uint convS2M(Fcall f, Byte[] pkt)
		{
			uint size, i, pp;
			
			size = sizeS2M(f);
			if(size == 0)
				return 0;
			if(size > pkt.Length)
				return 0;
			pp = 0;
			putuint(pkt, pp, size);
			pp += (uint)proto.BIT32SZ;
			pkt[pp] = f.type;
			pp += (uint)proto.BIT8SZ;
			putushort(pkt, pp, f.tag);
			pp += (uint)proto.BIT16SZ;
			
			switch(f.type) {
			default:
				return 0;
			case (byte)proto.Tversion:
				putuint(pkt, pp, f.msize);
				pp += (uint)proto.BIT32SZ;
				putstring(pkt, pp, f.version);
				pp += (uint)proto.BIT16SZ + (uint)f.version.Length;
				break;
			case (byte)proto.Tflush:
				putushort(pkt, pp, f.oldtag);
				pp += (uint)proto.BIT16SZ;
				break;
			case (byte)proto.Tauth:
				putuint(pkt, pp, (uint)f.afid);
				pp += (uint)proto.BIT32SZ;
				putstring(pkt, pp, f.uname);
				pp += (uint)proto.BIT16SZ + (uint)f.uname.Length;
				putstring(pkt, pp, f.aname);
				pp += (uint)proto.BIT16SZ + (uint)f.aname.Length;
				break;
			case (byte)proto.Tattach:
				putuint(pkt, pp, (uint)f.fid);
				pp += (uint)proto.BIT32SZ;
				putuint(pkt, pp, (uint)f.afid);
				pp += (uint)proto.BIT32SZ;
				putstring(pkt, pp, f.uname);
				pp += (uint)proto.BIT16SZ + (uint)f.uname.Length;
				putstring(pkt, pp, f.aname);
				pp += (uint)proto.BIT16SZ + (uint)f.aname.Length;
				break;
			case (byte)proto.Twalk:
				putuint(pkt, pp, (uint)f.fid);
				pp += (uint)proto.BIT32SZ;
				putuint(pkt, pp, (uint)f.newfid);
				pp += (uint)proto.BIT32SZ;
				putushort(pkt, pp, f.nwname);
				pp += (uint)proto.BIT16SZ;
				if(f.nwname > (uint)proto.MAXWELEM)
					return 0;
				for(i = 0; i < f.nwname; i++) {
					putstring(pkt, pp, f.wname[i]);
					pp += (uint)proto.BIT16SZ + (uint)f.wname[i].Length;
				}
				break;
			case (byte)proto.Topen:
				putuint(pkt, pp, (uint)f.fid);
				pp += (uint)proto.BIT32SZ;
				pkt[pp] = f.mode;
				pp += (uint)proto.BIT8SZ;
				break;
			case (byte)proto.Tcreate:
				putuint(pkt, pp, (uint)f.fid);
				pp += (uint)proto.BIT32SZ;
				putstring(pkt, pp, f.name);
				pp += (uint)proto.BIT16SZ + (uint)f.name.Length;
				putuint(pkt, pp, f.perm);
				pp += (uint)proto.BIT32SZ;
				pkt[pp] = f.mode;
				pp += (uint)proto.BIT8SZ;
				break;
			case (byte)proto.Tread:
				putuint(pkt, pp, (uint)f.fid);
				pp += (uint)proto.BIT32SZ;
				putulong(pkt, pp, f.offset);
				pp += (uint)proto.BIT64SZ;
				putuint(pkt, pp, f.count);
				pp += (uint)proto.BIT32SZ;
				break;
			case (byte)proto.Twrite:
				putuint(pkt, pp, (uint)f.fid);
				pp += (uint)proto.BIT32SZ;
				putulong(pkt, pp, f.offset);
				pp += (uint)proto.BIT64SZ;
				putuint(pkt, pp, f.count);
				pp += (uint)proto.BIT32SZ;
				Array.Copy(f.data, 0, pkt, pp, f.count);
				pp += f.count;
				break;
			case (byte)proto.Tclunk:
			case (byte)proto.Tremove:
			case (byte)proto.Tstat:
				putuint(pkt, pp, (uint)f.fid);
				pp += (uint)proto.BIT32SZ;
				break;
			case (byte)proto.Twstat:
				putuint(pkt, pp, (uint)f.fid);
				pp += (uint)proto.BIT32SZ;
				putushort(pkt, pp, f.nstat);
				pp += (uint)proto.BIT16SZ;
				Array.Copy(f.stat, 0, pkt, pp, f.nstat);
				pp += f.nstat;
				break;

			case (byte)proto.Rversion:
				putuint(pkt, pp, f.msize);
				pp += (uint)proto.BIT32SZ;
				putstring(pkt, pp, f.version);
				pp += (uint)proto.BIT16SZ + (uint)f.version.Length;
				break;
			case (byte)proto.Rerror:
				putstring(pkt, pp, f.ename);
				pp += (uint)proto.BIT16SZ + (uint)f.ename.Length;
				break;
			case (byte)proto.Rflush:
			case (byte)proto.Rclunk:
			case (byte)proto.Rremove:
			case (byte)proto.Rwstat:
				break;
			case (byte)proto.Rauth:
				putqid(pkt, pp, f.aqid);
				pp += (uint)proto.QIDSZ;
				break;
			case (byte)proto.Rattach:
				putqid(pkt, pp, f.qid);
				pp += (uint)proto.QIDSZ;
				break;
			case (byte)proto.Rwalk:
				putushort(pkt, pp, f.nwqid);
				pp += (uint)proto.BIT16SZ;
				if(f.nwqid > (uint)proto.MAXWELEM)
					return 0;
				for(i = 0; i < f.nwqid; i++) {
					putqid(pkt, pp, f.wqid[i]);
					pp += (uint)proto.QIDSZ;
				}
				break;
			case (byte)proto.Ropen:
			case (byte)proto.Rcreate:
				putqid(pkt, pp, f.qid);
				pp += (uint)proto.QIDSZ;
				putuint(pkt, pp, f.iounit);
				pp += (uint)proto.BIT32SZ;
				break;
			case (byte)proto.Rread:
				putuint(pkt, pp, f.count);
				pp += (uint)proto.BIT32SZ;
				Array.Copy(f.data, 0, pkt, pp, f.count);
				pp += f.count;
				break;
			case (byte)proto.Rwrite:
				putuint(pkt, pp, f.count);
				pp += (uint)proto.BIT32SZ;
				break;
			case (byte)proto.Rstat:
				putushort(pkt, pp, f.nstat);
				pp += (uint)proto.BIT16SZ;
				Array.Copy(f.stat, 0, pkt, pp, f.nstat);
				pp += f.nstat;
				break;
			}
			if(size != pp)
				return 0;
			return size;
		}

		public Dir convM2D(Byte[] stat, uint pp)
		{
			Dir d;
			
			d = new Dir();

			if(stat.Length < (int)proto.STATFIXLEN)
				return d;
			
			pp += (uint)proto.BIT16SZ;
			d.type = getushort(stat, pp);
			pp += (uint)proto.BIT16SZ;
			d.dev = getuint(stat, pp);
			pp += (uint)proto.BIT32SZ;
			d.qid = getqid(stat, pp);
			pp += (uint)proto.QIDSZ;
			d.mode = getuint(stat, pp);
			pp += (uint)proto.BIT32SZ;
			d.atime = getuint(stat, pp);
			pp += (uint)proto.BIT32SZ;
			d.mtime = getuint(stat, pp);
			pp += (uint)proto.BIT32SZ;
			d.length = getulong(stat, pp);
			pp += (uint)proto.BIT64SZ;
			d.name = getstring(stat, pp);
			pp += (uint)proto.BIT16SZ + (uint)d.name.Length;
			d.uid = getstring(stat, pp);
			pp += (uint)proto.BIT16SZ + (uint)d.uid.Length;
			d.gid = getstring(stat, pp);
			pp += (uint)proto.BIT16SZ + (uint)d.gid.Length;
			d.muid = getstring(stat, pp);
			pp += (uint)proto.BIT16SZ + (uint)d.muid.Length;

			d.status = 1;
			return d;
		}
		
		public uint sizeD2M(Dir d)
		{
			return (uint)proto.STATFIXLEN + (uint)d.name.Length + (uint)d.uid.Length +
					(uint)d.gid.Length + (uint)d.muid.Length;
		}
		
		public uint convD2M(Dir d, Byte[] stat)
		{
			uint pp, len;

			pp = 0;
			len = sizeD2M(d);

			if(len > stat.Length)
				return 0;
			
			putushort(stat, pp, (ushort)(len - (uint)proto.BIT16SZ));
			pp += (uint)proto.BIT16SZ;
			putushort(stat, pp, d.type);
			pp += (uint)proto.BIT16SZ;
			putuint(stat, pp, d.dev);
			pp += (uint)proto.BIT16SZ;
			stat[pp] = d.qid.type;
			pp += (uint)proto.BIT8SZ;
			putuint(stat, pp, d.qid.vers);
			pp += (uint)proto.BIT32SZ;
			putulong(stat, pp, d.qid.path);
			pp += (uint)proto.BIT64SZ;
			putuint(stat, pp, d.mode);
			pp += (uint)proto.BIT32SZ;
			putuint(stat, pp, d.atime);
			pp += (uint)proto.BIT32SZ;
			putuint(stat, pp, d.mtime);
			pp += (uint)proto.BIT32SZ;
			putulong(stat, pp, d.length);
			pp += (uint)proto.BIT64SZ;
			putstring(stat, pp, d.name);
			pp += (uint)proto.BIT16SZ + (uint)d.name.Length;
			putstring(stat, pp, d.uid);
			pp += (uint)proto.BIT16SZ + (uint)d.uid.Length;
			putstring(stat, pp, d.gid);
			pp += (uint)proto.BIT16SZ + (uint)d.gid.Length;
			putstring(stat, pp, d.muid);
			pp += (uint)proto.BIT16SZ + (uint)d.muid.Length;

			if(len != pp + 1)
				return 0;
				
			return pp + 1;
		}

		public Dir[] dols(Byte[] pkt)
		{
			Dir[] ret;
			uint pp, i;

			pp = 0;
			i = 0;

			for(i = 0, pp = 0; pp < pkt.Length; i++)
				pp += getushort(pkt, pp) + (uint)proto.BIT16SZ;

			ret = new Dir[i];
			i = 0;
			pp = 0;
			for(i = 0, pp = 0; pp < pkt.Length; i++) {
				ret[i] = convM2D(pkt, pp);
				pp += getushort(pkt, pp) + (uint)proto.BIT16SZ;
			}
			
			return ret;
		}

		public void dofid()
		{
			int cfid;

			doclunk(cwd);
			cfid = cwd;
			cwd = fid;
			fid = cfid;
		}

		public void do9p()
		{
			convS2M(fin, pktin);
			send9pmsg(pktin);
			pktout = read9pmsg();
			fout = convM2S(pktout);
		}

		public void doversion()
		{
			fin.type = (byte)proto.Tversion;
			fin.tag = 65535;
			fin.msize = mmsgsz;
			fin.version = "9P2000";
			do9p();
			if(fout.type == (sbyte)proto.Rerror)
				throw new ninepexception("Error on Tversion");

			if(fout.msize < mmsgsz) {
				mmsgsz = fout.msize;
				mdatasz = fout.msize + (uint)proto.IOHDRSIZE;
			}
		}
		
		public void doauth()
		{
			fin.type = (byte)proto.Tauth;
			fin.tag = ++tag;
			fin.afid = afid;
			fin.uname = uname;
			fin.aname = aname;
			do9p();
			if(fout.type == (sbyte)proto.Rauth)
				throw new ninepexception("Error, auth not supported for now");
		}
		
		public void doattach()
		{
			fin.type = (byte)proto.Tattach;
			fin.tag = ++tag;
			fin.fid = root;
			fin.afid = afid;
			fin.uname = uname;
			fin.aname = aname;
			do9p();
			if(fout.type == (sbyte)proto.Rerror)
				throw new ninepexception("Error, attach failed");
		}
		
		public void doswalk(int fid, int newfid, string[] path)
		{
			fin.type = (byte)proto.Twalk;
			fin.tag = ++tag;
			fin.fid = fid;
			fin.newfid = newfid;
			fin.nwname = (ushort)path.Length;
			fin.wname = path;
			do9p();
			if(fout.type == (sbyte)proto.Rerror)
				throw new ninepexception("Error, walk failed");
		}
		
		public void dowalk(int fid, int newfid, string[] path)
		{
			uint i;
			string[] lss;
			
			for(i = 0; i <= path.Length; i += (uint)proto.MAXWELEM) {
				lss = new string[(path.Length - i > (uint)proto.MAXWELEM)
									? (uint)proto.MAXWELEM : path.Length - i];
				Array.Copy(path, i, lss, 0, lss.Length);
				doswalk(fid, newfid, lss);
				if(fid != root && newfid != ffid)
					dofid();
			}
		}
		
		public void dostat(int fid)
		{
			fin.type = (byte)proto.Tstat;
			fin.tag = ++tag;
			fin.fid = fid;
			do9p();
			if(fout.type == (sbyte)proto.Rerror)
				throw new ninepexception("Error, stat failed");

			dir = convM2D(fout.stat, 0);
		}
		
		public void doclunk(int fid)
		{
			fin.type = (byte)proto.Tclunk;
			fin.tag = ++tag;
			fin.fid = fid;
			do9p();
			if(fout.type == (sbyte)proto.Rerror)
				throw new ninepexception("Error, clunk failed");
		}
		
		public void doopen(int fid, byte mode)
		{
			fin.type = (byte)proto.Topen;
			fin.tag = ++tag;
			fin.fid = fid;
			fin.mode = mode;
			fin.iounit = 0;
			do9p();
			if(fout.type == (sbyte)proto.Rerror)
				throw new ninepexception("Error, open failed");
				
			if(fout.iounit != 0) {
				mmsgsz = fout.iounit + (uint)proto.IOHDRSIZE;
				mdatasz = fout.iounit;
			}
		}

		public void dosread(int fid, ulong offset, uint count)
		{
			fin.type = (byte)proto.Tread;
			fin.tag = ++tag;
			fin.fid = fid;
			fin.offset = offset;
			fin.count = count;
			do9p();
			if(fout.type == (sbyte)proto.Rerror)
				throw new ninepexception("Error, read failed");
		}
		
		public void doread(int fid, ulong offset, uint count)
		{
			Byte[] strip;
			uint len;
			
			len = 0;
			readbuf = new Byte[count];
			
			while(len < count) {
				dosread(fid, offset, ((count - len) > mdatasz) ? mdatasz : count);
				Array.Copy(fout.data, 0, readbuf, len, fout.data.Length);
				len += (uint)fout.data.Length;
				if(fout.data.Length != mdatasz && len < count)
					break;
			}
			
			if(len < count) {
				strip = new Byte[len];
				Array.Copy(readbuf, 0, strip, 0, len);
				readbuf = strip;
			}
		}
		
		public void doswrite(int fid, ulong offset, uint count, Byte[] data)
		{
			fin.type = (byte)proto.Twrite;
			fin.tag = ++tag;
			fin.fid = fid;
			fin.offset = offset;
			fin.count = count;
			fin.data = data;
			do9p();
			if(fout.type == (sbyte)proto.Rerror)
				throw new ninepexception("Error, write failed");
		}
		
		public void dowrite(int fid, ulong offset, uint count, Byte[] data)
		{
			Byte[] strip;
			uint len;
			
			len = 0;
			
			while(len < count) {
				strip = new Byte[((count - len) > mdatasz) ? mdatasz : count];
				Array.Copy(data, len, strip, 0, strip.Length);
				doswrite(fid, offset, (uint)strip.Length, strip);
				len += (uint)strip.Length;
			}
		}
	}

	class MainClass
	{
		public static void Main(string[] args)
		{
			ninepc.ninep test;
			string cmd, server;
			int i;
			uint offset;
			Dir[] dirs;
			string[] lss, lsc;

			test = new ninepc.ninep();
			server = "sources.cs.bell-labs.com";
			
			try {
				test.connect(server, 564);
				test.doversion();
				test.doauth();
				test.doattach();
				test.dowalk(test.root, test.cwd, new string[0]);

				for(;;) {
					Console.Write("{0}% ", server);
					cmd = Console.ReadLine();
					if(cmd.StartsWith("ls")) {
						test.dowalk(test.cwd, test.ffid, new string[] {"."});
						test.doopen(test.ffid, 0x00);
						test.doread(test.ffid, 0, (uint)test.mdatasz);
						dirs = test.dols(test.readbuf);
						foreach(Dir d in dirs)
							Console.WriteLine("{0} {1} {2} {3} {4}", test.modestr(d.mode), d.uid,
														d.gid, d.length, d.name);
						test.doclunk(test.ffid);
						continue;
					}
					
					if(cmd.StartsWith("cd")) {
						lss = cmd.Split(" ".ToCharArray());
						if(lss.Length < 2)
							continue;
						lsc = lss[1].Split("/".ToCharArray());
						test.dowalk(test.cwd, test.fid, lsc);
						continue;
					}

					if(cmd.StartsWith("cat")) {
						lss = cmd.Split(" ".ToCharArray());
						Array.Copy(lss, 1, lss, 0, lss.Length - 1);
						for(i = 0; i < (lss.Length - 1); i++) {
							offset = 0;
							test.dowalk(test.cwd, test.ffid, new string[] {lss[i]});
							test.dostat(test.ffid);
							test.doopen(test.ffid, 0x00);
							test.doread(test.ffid, offset, (uint)test.dir.length);
							Console.WriteLine(test.convstring(test.readbuf));
							test.doclunk(test.ffid);
						}
					}
					
					if(cmd.StartsWith("q"))
						break;
				}

				test.doclunk(test.cwd);
				test.doclunk(test.root);
				
				test.shutdown();
			} catch(Exception ex) {
				Console.WriteLine("Error main: {0}", ex.ToString());
			}	
		}
	}
}
