// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: strangelove/horcrux/remote_signer.proto

package proto

import (
	context "context"
	fmt "fmt"
	grpc1 "github.com/cosmos/gogoproto/grpc"
	proto "github.com/cosmos/gogoproto/proto"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	io "io"
	math "math"
	math_bits "math/bits"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

type PubKeyRequest struct {
	ChainId string `protobuf:"bytes,1,opt,name=chain_id,json=chainId,proto3" json:"chain_id,omitempty"`
}

func (m *PubKeyRequest) Reset()         { *m = PubKeyRequest{} }
func (m *PubKeyRequest) String() string { return proto.CompactTextString(m) }
func (*PubKeyRequest) ProtoMessage()    {}
func (*PubKeyRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_afd7664cd19b584a, []int{0}
}
func (m *PubKeyRequest) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *PubKeyRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_PubKeyRequest.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *PubKeyRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PubKeyRequest.Merge(m, src)
}
func (m *PubKeyRequest) XXX_Size() int {
	return m.Size()
}
func (m *PubKeyRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_PubKeyRequest.DiscardUnknown(m)
}

var xxx_messageInfo_PubKeyRequest proto.InternalMessageInfo

func (m *PubKeyRequest) GetChainId() string {
	if m != nil {
		return m.ChainId
	}
	return ""
}

type PubKeyResponse struct {
	PubKey []byte `protobuf:"bytes,1,opt,name=pub_key,json=pubKey,proto3" json:"pub_key,omitempty"`
}

func (m *PubKeyResponse) Reset()         { *m = PubKeyResponse{} }
func (m *PubKeyResponse) String() string { return proto.CompactTextString(m) }
func (*PubKeyResponse) ProtoMessage()    {}
func (*PubKeyResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_afd7664cd19b584a, []int{1}
}
func (m *PubKeyResponse) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *PubKeyResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_PubKeyResponse.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *PubKeyResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PubKeyResponse.Merge(m, src)
}
func (m *PubKeyResponse) XXX_Size() int {
	return m.Size()
}
func (m *PubKeyResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_PubKeyResponse.DiscardUnknown(m)
}

var xxx_messageInfo_PubKeyResponse proto.InternalMessageInfo

func (m *PubKeyResponse) GetPubKey() []byte {
	if m != nil {
		return m.PubKey
	}
	return nil
}

func init() {
	proto.RegisterType((*PubKeyRequest)(nil), "strangelove.horcrux.PubKeyRequest")
	proto.RegisterType((*PubKeyResponse)(nil), "strangelove.horcrux.PubKeyResponse")
}

func init() {
	proto.RegisterFile("strangelove/horcrux/remote_signer.proto", fileDescriptor_afd7664cd19b584a)
}

var fileDescriptor_afd7664cd19b584a = []byte{
	// 279 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x52, 0x2f, 0x2e, 0x29, 0x4a,
	0xcc, 0x4b, 0x4f, 0xcd, 0xc9, 0x2f, 0x4b, 0xd5, 0xcf, 0xc8, 0x2f, 0x4a, 0x2e, 0x2a, 0xad, 0xd0,
	0x2f, 0x4a, 0xcd, 0xcd, 0x2f, 0x49, 0x8d, 0x2f, 0xce, 0x4c, 0xcf, 0x4b, 0x2d, 0xd2, 0x2b, 0x28,
	0xca, 0x2f, 0xc9, 0x17, 0x12, 0x46, 0x52, 0xa8, 0x07, 0x55, 0x28, 0xa5, 0x84, 0x4d, 0x77, 0x72,
	0x3e, 0xb2, 0x46, 0x25, 0x2d, 0x2e, 0xde, 0x80, 0xd2, 0x24, 0xef, 0xd4, 0xca, 0xa0, 0xd4, 0xc2,
	0xd2, 0xd4, 0xe2, 0x12, 0x21, 0x49, 0x2e, 0x8e, 0xe4, 0x8c, 0xc4, 0xcc, 0xbc, 0xf8, 0xcc, 0x14,
	0x09, 0x46, 0x05, 0x46, 0x0d, 0xce, 0x20, 0x76, 0x30, 0xdf, 0x33, 0x45, 0x49, 0x93, 0x8b, 0x0f,
	0xa6, 0xb6, 0xb8, 0x20, 0x3f, 0xaf, 0x38, 0x55, 0x48, 0x9c, 0x8b, 0xbd, 0xa0, 0x34, 0x29, 0x3e,
	0x3b, 0xb5, 0x12, 0xac, 0x96, 0x27, 0x88, 0xad, 0x00, 0xac, 0xc0, 0x68, 0x0f, 0x23, 0x17, 0x4f,
	0x10, 0xd8, 0x9d, 0xc1, 0x60, 0xdb, 0x84, 0x82, 0xb9, 0xd8, 0x20, 0x7a, 0x85, 0x94, 0xf4, 0xb0,
	0xb8, 0x55, 0x0f, 0xc5, 0x11, 0x52, 0xca, 0x78, 0xd5, 0x40, 0x2c, 0x57, 0x62, 0x10, 0x0a, 0xe7,
	0x62, 0x01, 0x19, 0x2f, 0xa4, 0x8a, 0x55, 0x39, 0x48, 0xca, 0x29, 0x27, 0x3f, 0x39, 0x1b, 0x66,
	0xaa, 0x1a, 0x21, 0x65, 0x30, 0x83, 0x9d, 0x02, 0x4f, 0x3c, 0x92, 0x63, 0xbc, 0xf0, 0x48, 0x8e,
	0xf1, 0xc1, 0x23, 0x39, 0xc6, 0x09, 0x8f, 0xe5, 0x18, 0x2e, 0x3c, 0x96, 0x63, 0xb8, 0xf1, 0x58,
	0x8e, 0x21, 0xca, 0x3c, 0x3d, 0xb3, 0x24, 0xa3, 0x34, 0x49, 0x2f, 0x39, 0x3f, 0x57, 0x1f, 0xc9,
	0x34, 0xdd, 0xb2, 0xd4, 0xbc, 0x92, 0xd2, 0xa2, 0xd4, 0x62, 0x78, 0x38, 0x97, 0x19, 0xeb, 0x43,
	0x02, 0x5a, 0x1f, 0x1c, 0xd0, 0x49, 0x6c, 0x60, 0xca, 0x18, 0x10, 0x00, 0x00, 0xff, 0xff, 0x1e,
	0xa5, 0x90, 0x75, 0xd3, 0x01, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// RemoteSignerClient is the client API for RemoteSigner service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type RemoteSignerClient interface {
	PubKey(ctx context.Context, in *PubKeyRequest, opts ...grpc.CallOption) (*PubKeyResponse, error)
	Sign(ctx context.Context, in *SignBlockRequest, opts ...grpc.CallOption) (*SignBlockResponse, error)
}

type remoteSignerClient struct {
	cc grpc1.ClientConn
}

func NewRemoteSignerClient(cc grpc1.ClientConn) RemoteSignerClient {
	return &remoteSignerClient{cc}
}

func (c *remoteSignerClient) PubKey(ctx context.Context, in *PubKeyRequest, opts ...grpc.CallOption) (*PubKeyResponse, error) {
	out := new(PubKeyResponse)
	err := c.cc.Invoke(ctx, "/strangelove.horcrux.RemoteSigner/PubKey", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *remoteSignerClient) Sign(ctx context.Context, in *SignBlockRequest, opts ...grpc.CallOption) (*SignBlockResponse, error) {
	out := new(SignBlockResponse)
	err := c.cc.Invoke(ctx, "/strangelove.horcrux.RemoteSigner/Sign", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// RemoteSignerServer is the server API for RemoteSigner service.
type RemoteSignerServer interface {
	PubKey(context.Context, *PubKeyRequest) (*PubKeyResponse, error)
	Sign(context.Context, *SignBlockRequest) (*SignBlockResponse, error)
}

// UnimplementedRemoteSignerServer can be embedded to have forward compatible implementations.
type UnimplementedRemoteSignerServer struct {
}

func (*UnimplementedRemoteSignerServer) PubKey(ctx context.Context, req *PubKeyRequest) (*PubKeyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method PubKey not implemented")
}
func (*UnimplementedRemoteSignerServer) Sign(ctx context.Context, req *SignBlockRequest) (*SignBlockResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Sign not implemented")
}

func RegisterRemoteSignerServer(s grpc1.Server, srv RemoteSignerServer) {
	s.RegisterService(&_RemoteSigner_serviceDesc, srv)
}

func _RemoteSigner_PubKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PubKeyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RemoteSignerServer).PubKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/strangelove.horcrux.RemoteSigner/PubKey",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RemoteSignerServer).PubKey(ctx, req.(*PubKeyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _RemoteSigner_Sign_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SignBlockRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RemoteSignerServer).Sign(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/strangelove.horcrux.RemoteSigner/Sign",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RemoteSignerServer).Sign(ctx, req.(*SignBlockRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _RemoteSigner_serviceDesc = grpc.ServiceDesc{
	ServiceName: "strangelove.horcrux.RemoteSigner",
	HandlerType: (*RemoteSignerServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "PubKey",
			Handler:    _RemoteSigner_PubKey_Handler,
		},
		{
			MethodName: "Sign",
			Handler:    _RemoteSigner_Sign_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "strangelove/horcrux/remote_signer.proto",
}

func (m *PubKeyRequest) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *PubKeyRequest) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *PubKeyRequest) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.ChainId) > 0 {
		i -= len(m.ChainId)
		copy(dAtA[i:], m.ChainId)
		i = encodeVarintRemoteSigner(dAtA, i, uint64(len(m.ChainId)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *PubKeyResponse) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *PubKeyResponse) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *PubKeyResponse) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.PubKey) > 0 {
		i -= len(m.PubKey)
		copy(dAtA[i:], m.PubKey)
		i = encodeVarintRemoteSigner(dAtA, i, uint64(len(m.PubKey)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintRemoteSigner(dAtA []byte, offset int, v uint64) int {
	offset -= sovRemoteSigner(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *PubKeyRequest) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.ChainId)
	if l > 0 {
		n += 1 + l + sovRemoteSigner(uint64(l))
	}
	return n
}

func (m *PubKeyResponse) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.PubKey)
	if l > 0 {
		n += 1 + l + sovRemoteSigner(uint64(l))
	}
	return n
}

func sovRemoteSigner(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozRemoteSigner(x uint64) (n int) {
	return sovRemoteSigner(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *PubKeyRequest) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowRemoteSigner
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: PubKeyRequest: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: PubKeyRequest: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ChainId", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowRemoteSigner
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthRemoteSigner
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthRemoteSigner
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.ChainId = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipRemoteSigner(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthRemoteSigner
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *PubKeyResponse) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowRemoteSigner
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: PubKeyResponse: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: PubKeyResponse: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field PubKey", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowRemoteSigner
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthRemoteSigner
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthRemoteSigner
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.PubKey = append(m.PubKey[:0], dAtA[iNdEx:postIndex]...)
			if m.PubKey == nil {
				m.PubKey = []byte{}
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipRemoteSigner(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthRemoteSigner
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipRemoteSigner(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowRemoteSigner
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowRemoteSigner
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowRemoteSigner
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthRemoteSigner
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupRemoteSigner
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthRemoteSigner
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthRemoteSigner        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowRemoteSigner          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupRemoteSigner = fmt.Errorf("proto: unexpected end of group")
)