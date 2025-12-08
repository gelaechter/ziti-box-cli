# \InformationalApi

All URIs are relative to *https://demo.ziti.dev/edge/management/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**detail_spec**](InformationalApi.md#detail_spec) | **GET** /specs/{id} | Return a single spec resource
[**detail_spec_body**](InformationalApi.md#detail_spec_body) | **GET** /specs/{id}/spec | Returns the spec's file
[**list_enumerated_capabilities**](InformationalApi.md#list_enumerated_capabilities) | **GET** /enumerated-capabilities | Returns all capabilities this version of the controller is aware of, enabled or not.
[**list_root**](InformationalApi.md#list_root) | **GET** / | Returns version information
[**list_specs**](InformationalApi.md#list_specs) | **GET** /specs | Returns a list of API specs
[**list_summary**](InformationalApi.md#list_summary) | **GET** /summary | Returns a list of accessible resource counts
[**list_version**](InformationalApi.md#list_version) | **GET** /version | Returns version information



## detail_spec

> models::DetailSpecEnvelope detail_spec(id)
Return a single spec resource

Returns single spec resource embedded within the controller for consumption/documentation/code geneartion

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |

### Return type

[**models::DetailSpecEnvelope**](detailSpecEnvelope.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## detail_spec_body

> models::DetailSpecBodyEnvelope detail_spec_body(id)
Returns the spec's file

Return the body of the specification (i.e. Swagger, OpenAPI 2.0, 3.0, etc).

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |

### Return type

[**models::DetailSpecBodyEnvelope**](detailSpecBodyEnvelope.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: text/yaml, application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_enumerated_capabilities

> models::ListEnumeratedCapabilitiesEnvelope list_enumerated_capabilities()
Returns all capabilities this version of the controller is aware of, enabled or not.

### Parameters

This endpoint does not need any parameter.

### Return type

[**models::ListEnumeratedCapabilitiesEnvelope**](listEnumeratedCapabilitiesEnvelope.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_root

> models::ListVersionEnvelope list_root()
Returns version information

### Parameters

This endpoint does not need any parameter.

### Return type

[**models::ListVersionEnvelope**](listVersionEnvelope.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_specs

> models::ListSpecsEnvelope list_specs()
Returns a list of API specs

Returns a list of spec files embedded within the controller for consumption/documentation/code geneartion

### Parameters

This endpoint does not need any parameter.

### Return type

[**models::ListSpecsEnvelope**](listSpecsEnvelope.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_summary

> models::ListSummaryCountsEnvelope list_summary()
Returns a list of accessible resource counts

This endpoint is usefull for UIs that wish to display UI elements with counts.

### Parameters

This endpoint does not need any parameter.

### Return type

[**models::ListSummaryCountsEnvelope**](listSummaryCountsEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_version

> models::ListVersionEnvelope list_version()
Returns version information

### Parameters

This endpoint does not need any parameter.

### Return type

[**models::ListVersionEnvelope**](listVersionEnvelope.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

