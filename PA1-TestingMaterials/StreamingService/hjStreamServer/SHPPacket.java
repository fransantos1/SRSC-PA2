public class SHPPacket {
    private final int ver; // 4 bits max
    private final int release; // 4 bits max
    private final int msgType; // 8 bits max
    private final byte[] msg;


    public SHPPacket(int ver, int release, int msgType, byte[] msg) {
        this.ver = ver;
        this.release = release;
        this.msgType = msgType;
        this.msg = msg.clone();
    }

    public int getVer() {
        return ver;
    }

    public int getrelease() {
        return release;
    }

    public int getMsgType() {
        return msgType;
    }

    public byte[] getMsg() {
        return msg.clone();
    }

    public int getTotalSize() {
        return 2 + msg.length; 
    }

    public byte[] toByteArray() {
        byte[] packet = new byte[getTotalSize()];
        packet[0] = (byte) ((ver << 4) | (release)); 
        packet[1] = (byte) (msgType);
        System.arraycopy(msg, 0, packet, 2, msg.length);
        return packet;
    
    }
    public static SHPPacket fromByteArray(byte[] packet) {

        int ver = (packet[0] >> 4) & 0x0F;  
        int release = packet[0] & 0x0F;     
        int msgType = packet[1] & 0xFF;  
        byte[] msg = new byte[packet.length - 2]; 
        System.arraycopy(packet, 2, msg, 0, msg.length);
        return new SHPPacket(ver, release, msgType, msg);
    }
    

    @Override
    public String toString() {
        return "SHPPacket{" +
               "ver=" + ver +
               ", release=" + release +
               ", msgType=" + msgType +
               '}';
    }
}
