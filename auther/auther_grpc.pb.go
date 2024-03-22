// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v4.25.3
// source: auther.proto

package auther

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	Auther_IsUniqueUserIdentifier_FullMethodName = "/Auther/IsUniqueUserIdentifier"
	Auther_Login_FullMethodName                  = "/Auther/Login"
	Auther_Logout_FullMethodName                 = "/Auther/Logout"
	Auther_LogoutAll_FullMethodName              = "/Auther/LogoutAll"
	Auther_Refresh_FullMethodName                = "/Auther/Refresh"
	Auther_Register_FullMethodName               = "/Auther/Register"
	Auther_Sessions_FullMethodName               = "/Auther/Sessions"
	Auther_Profile_FullMethodName                = "/Auther/Profile"
	Auther_SendSmsOTP_FullMethodName             = "/Auther/SendSmsOTP"
	Auther_VerifySmsOTP_FullMethodName           = "/Auther/VerifySmsOTP"
	Auther_SendEmailOTP_FullMethodName           = "/Auther/SendEmailOTP"
	Auther_VerifyEmailOTP_FullMethodName         = "/Auther/VerifyEmailOTP"
)

// AutherClient is the client API for Auther service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type AutherClient interface {
	IsUniqueUserIdentifier(ctx context.Context, in *IsUniqueUserIdentifierRequest, opts ...grpc.CallOption) (*IsUniqueUserIdentifierResponse, error)
	Login(ctx context.Context, in *LoginRequest, opts ...grpc.CallOption) (*AuthenticationData, error)
	Logout(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*SuccessResponse, error)
	LogoutAll(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*SuccessResponse, error)
	Refresh(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*AuthenticationData, error)
	Register(ctx context.Context, in *RegisterRequest, opts ...grpc.CallOption) (*AuthenticationData, error)
	Sessions(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*SessionsResponse, error)
	Profile(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*ProfileResponse, error)
	SendSmsOTP(ctx context.Context, in *SendSmSOTPRequest, opts ...grpc.CallOption) (*SuccessResponse, error)
	VerifySmsOTP(ctx context.Context, in *VerifySmsOtpRequest, opts ...grpc.CallOption) (*SuccessResponse, error)
	SendEmailOTP(ctx context.Context, in *SendEmailOTPRequest, opts ...grpc.CallOption) (*OTPValidationResponse, error)
	VerifyEmailOTP(ctx context.Context, in *VerifyEmailOtpRequest, opts ...grpc.CallOption) (*OTPValidationResponse, error)
}

type autherClient struct {
	cc grpc.ClientConnInterface
}

func NewAutherClient(cc grpc.ClientConnInterface) AutherClient {
	return &autherClient{cc}
}

func (c *autherClient) IsUniqueUserIdentifier(ctx context.Context, in *IsUniqueUserIdentifierRequest, opts ...grpc.CallOption) (*IsUniqueUserIdentifierResponse, error) {
	out := new(IsUniqueUserIdentifierResponse)
	err := c.cc.Invoke(ctx, Auther_IsUniqueUserIdentifier_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *autherClient) Login(ctx context.Context, in *LoginRequest, opts ...grpc.CallOption) (*AuthenticationData, error) {
	out := new(AuthenticationData)
	err := c.cc.Invoke(ctx, Auther_Login_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *autherClient) Logout(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*SuccessResponse, error) {
	out := new(SuccessResponse)
	err := c.cc.Invoke(ctx, Auther_Logout_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *autherClient) LogoutAll(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*SuccessResponse, error) {
	out := new(SuccessResponse)
	err := c.cc.Invoke(ctx, Auther_LogoutAll_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *autherClient) Refresh(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*AuthenticationData, error) {
	out := new(AuthenticationData)
	err := c.cc.Invoke(ctx, Auther_Refresh_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *autherClient) Register(ctx context.Context, in *RegisterRequest, opts ...grpc.CallOption) (*AuthenticationData, error) {
	out := new(AuthenticationData)
	err := c.cc.Invoke(ctx, Auther_Register_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *autherClient) Sessions(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*SessionsResponse, error) {
	out := new(SessionsResponse)
	err := c.cc.Invoke(ctx, Auther_Sessions_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *autherClient) Profile(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*ProfileResponse, error) {
	out := new(ProfileResponse)
	err := c.cc.Invoke(ctx, Auther_Profile_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *autherClient) SendSmsOTP(ctx context.Context, in *SendSmSOTPRequest, opts ...grpc.CallOption) (*SuccessResponse, error) {
	out := new(SuccessResponse)
	err := c.cc.Invoke(ctx, Auther_SendSmsOTP_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *autherClient) VerifySmsOTP(ctx context.Context, in *VerifySmsOtpRequest, opts ...grpc.CallOption) (*SuccessResponse, error) {
	out := new(SuccessResponse)
	err := c.cc.Invoke(ctx, Auther_VerifySmsOTP_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *autherClient) SendEmailOTP(ctx context.Context, in *SendEmailOTPRequest, opts ...grpc.CallOption) (*OTPValidationResponse, error) {
	out := new(OTPValidationResponse)
	err := c.cc.Invoke(ctx, Auther_SendEmailOTP_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *autherClient) VerifyEmailOTP(ctx context.Context, in *VerifyEmailOtpRequest, opts ...grpc.CallOption) (*OTPValidationResponse, error) {
	out := new(OTPValidationResponse)
	err := c.cc.Invoke(ctx, Auther_VerifyEmailOTP_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AutherServer is the server API for Auther service.
// All implementations must embed UnimplementedAutherServer
// for forward compatibility
type AutherServer interface {
	IsUniqueUserIdentifier(context.Context, *IsUniqueUserIdentifierRequest) (*IsUniqueUserIdentifierResponse, error)
	Login(context.Context, *LoginRequest) (*AuthenticationData, error)
	Logout(context.Context, *Empty) (*SuccessResponse, error)
	LogoutAll(context.Context, *Empty) (*SuccessResponse, error)
	Refresh(context.Context, *Empty) (*AuthenticationData, error)
	Register(context.Context, *RegisterRequest) (*AuthenticationData, error)
	Sessions(context.Context, *Empty) (*SessionsResponse, error)
	Profile(context.Context, *Empty) (*ProfileResponse, error)
	SendSmsOTP(context.Context, *SendSmSOTPRequest) (*SuccessResponse, error)
	VerifySmsOTP(context.Context, *VerifySmsOtpRequest) (*SuccessResponse, error)
	SendEmailOTP(context.Context, *SendEmailOTPRequest) (*OTPValidationResponse, error)
	VerifyEmailOTP(context.Context, *VerifyEmailOtpRequest) (*OTPValidationResponse, error)
	mustEmbedUnimplementedAutherServer()
}

// UnimplementedAutherServer must be embedded to have forward compatible implementations.
type UnimplementedAutherServer struct {
}

func (UnimplementedAutherServer) IsUniqueUserIdentifier(context.Context, *IsUniqueUserIdentifierRequest) (*IsUniqueUserIdentifierResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method IsUniqueUserIdentifier not implemented")
}
func (UnimplementedAutherServer) Login(context.Context, *LoginRequest) (*AuthenticationData, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Login not implemented")
}
func (UnimplementedAutherServer) Logout(context.Context, *Empty) (*SuccessResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Logout not implemented")
}
func (UnimplementedAutherServer) LogoutAll(context.Context, *Empty) (*SuccessResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method LogoutAll not implemented")
}
func (UnimplementedAutherServer) Refresh(context.Context, *Empty) (*AuthenticationData, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Refresh not implemented")
}
func (UnimplementedAutherServer) Register(context.Context, *RegisterRequest) (*AuthenticationData, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Register not implemented")
}
func (UnimplementedAutherServer) Sessions(context.Context, *Empty) (*SessionsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Sessions not implemented")
}
func (UnimplementedAutherServer) Profile(context.Context, *Empty) (*ProfileResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Profile not implemented")
}
func (UnimplementedAutherServer) SendSmsOTP(context.Context, *SendSmSOTPRequest) (*SuccessResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SendSmsOTP not implemented")
}
func (UnimplementedAutherServer) VerifySmsOTP(context.Context, *VerifySmsOtpRequest) (*SuccessResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method VerifySmsOTP not implemented")
}
func (UnimplementedAutherServer) SendEmailOTP(context.Context, *SendEmailOTPRequest) (*OTPValidationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SendEmailOTP not implemented")
}
func (UnimplementedAutherServer) VerifyEmailOTP(context.Context, *VerifyEmailOtpRequest) (*OTPValidationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method VerifyEmailOTP not implemented")
}
func (UnimplementedAutherServer) mustEmbedUnimplementedAutherServer() {}

// UnsafeAutherServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to AutherServer will
// result in compilation errors.
type UnsafeAutherServer interface {
	mustEmbedUnimplementedAutherServer()
}

func RegisterAutherServer(s grpc.ServiceRegistrar, srv AutherServer) {
	s.RegisterService(&Auther_ServiceDesc, srv)
}

func _Auther_IsUniqueUserIdentifier_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(IsUniqueUserIdentifierRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AutherServer).IsUniqueUserIdentifier(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Auther_IsUniqueUserIdentifier_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AutherServer).IsUniqueUserIdentifier(ctx, req.(*IsUniqueUserIdentifierRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Auther_Login_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LoginRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AutherServer).Login(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Auther_Login_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AutherServer).Login(ctx, req.(*LoginRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Auther_Logout_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AutherServer).Logout(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Auther_Logout_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AutherServer).Logout(ctx, req.(*Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _Auther_LogoutAll_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AutherServer).LogoutAll(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Auther_LogoutAll_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AutherServer).LogoutAll(ctx, req.(*Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _Auther_Refresh_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AutherServer).Refresh(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Auther_Refresh_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AutherServer).Refresh(ctx, req.(*Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _Auther_Register_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RegisterRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AutherServer).Register(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Auther_Register_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AutherServer).Register(ctx, req.(*RegisterRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Auther_Sessions_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AutherServer).Sessions(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Auther_Sessions_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AutherServer).Sessions(ctx, req.(*Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _Auther_Profile_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AutherServer).Profile(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Auther_Profile_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AutherServer).Profile(ctx, req.(*Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _Auther_SendSmsOTP_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SendSmSOTPRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AutherServer).SendSmsOTP(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Auther_SendSmsOTP_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AutherServer).SendSmsOTP(ctx, req.(*SendSmSOTPRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Auther_VerifySmsOTP_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(VerifySmsOtpRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AutherServer).VerifySmsOTP(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Auther_VerifySmsOTP_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AutherServer).VerifySmsOTP(ctx, req.(*VerifySmsOtpRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Auther_SendEmailOTP_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SendEmailOTPRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AutherServer).SendEmailOTP(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Auther_SendEmailOTP_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AutherServer).SendEmailOTP(ctx, req.(*SendEmailOTPRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Auther_VerifyEmailOTP_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(VerifyEmailOtpRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AutherServer).VerifyEmailOTP(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Auther_VerifyEmailOTP_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AutherServer).VerifyEmailOTP(ctx, req.(*VerifyEmailOtpRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// Auther_ServiceDesc is the grpc.ServiceDesc for Auther service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Auther_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "Auther",
	HandlerType: (*AutherServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "IsUniqueUserIdentifier",
			Handler:    _Auther_IsUniqueUserIdentifier_Handler,
		},
		{
			MethodName: "Login",
			Handler:    _Auther_Login_Handler,
		},
		{
			MethodName: "Logout",
			Handler:    _Auther_Logout_Handler,
		},
		{
			MethodName: "LogoutAll",
			Handler:    _Auther_LogoutAll_Handler,
		},
		{
			MethodName: "Refresh",
			Handler:    _Auther_Refresh_Handler,
		},
		{
			MethodName: "Register",
			Handler:    _Auther_Register_Handler,
		},
		{
			MethodName: "Sessions",
			Handler:    _Auther_Sessions_Handler,
		},
		{
			MethodName: "Profile",
			Handler:    _Auther_Profile_Handler,
		},
		{
			MethodName: "SendSmsOTP",
			Handler:    _Auther_SendSmsOTP_Handler,
		},
		{
			MethodName: "VerifySmsOTP",
			Handler:    _Auther_VerifySmsOTP_Handler,
		},
		{
			MethodName: "SendEmailOTP",
			Handler:    _Auther_SendEmailOTP_Handler,
		},
		{
			MethodName: "VerifyEmailOTP",
			Handler:    _Auther_VerifyEmailOTP_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "auther.proto",
}
