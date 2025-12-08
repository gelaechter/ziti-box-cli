# \WellKnownApi

All URIs are relative to *https://demo.ziti.dev/edge/management/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**list_well_known_cas**](WellKnownApi.md#list_well_known_cas) | **GET** /.well-known/est/cacerts | Get CA Cert Store



## list_well_known_cas

> String list_well_known_cas()
Get CA Cert Store

This endpoint is used during enrollments to bootstrap trust between enrolling clients and the Ziti Edge API. This endpoint returns a base64 encoded PKCS7 store. The content can be base64 decoded and parsed by any library that supports parsing PKCS7 stores. 

### Parameters

This endpoint does not need any parameter.

### Return type

**String**

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/pkcs7-mime

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

