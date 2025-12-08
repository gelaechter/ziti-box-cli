# \TracingApi

All URIs are relative to *https://demo.ziti.dev/edge/management/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**update_identity_tracing**](TracingApi.md#update_identity_tracing) | **PUT** /identities/{id}/trace | Enable/disable data flow tracing for an identity



## update_identity_tracing

> models::TraceDetailEnvelope update_identity_tracing(id, trace_spec)
Enable/disable data flow tracing for an identity

Allows an admin to enable/disable data flow tracing for an identity 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**trace_spec** | [**TraceSpec**](TraceSpec.md) | A traceSpec object | [required] |

### Return type

[**models::TraceDetailEnvelope**](traceDetailEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

