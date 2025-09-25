package api

import (
	"net/http"

	"proxy-distributor/internal/models"

	"github.com/gin-gonic/gin"
)

// SuccessResponse 返回成功响应
func SuccessResponse(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, models.APIResponse{
		Code:    200,
		Message: "成功",
		Data:    data,
	})
}

// ErrorResponse 返回错误响应
func ErrorResponse(c *gin.Context, code int, message string) {
	c.JSON(code, models.APIResponse{
		Code:    code,
		Message: message,
	})
}

// ValidationErrorResponse 返回参数验证错误响应
func ValidationErrorResponse(c *gin.Context, err error) {
	ErrorResponse(c, http.StatusBadRequest, "请求参数错误: "+err.Error())
}

// NotFoundResponse 返回资源不存在响应
func NotFoundResponse(c *gin.Context, resource string) {
	ErrorResponse(c, http.StatusNotFound, resource+"不存在")
}

// InternalErrorResponse 返回内部错误响应
func InternalErrorResponse(c *gin.Context, operation string, err error) {
	ErrorResponse(c, http.StatusInternalServerError, operation+"失败: "+err.Error())
}

// UnauthorizedResponse 返回未授权响应
func UnauthorizedResponse(c *gin.Context, message string) {
	ErrorResponse(c, http.StatusUnauthorized, message)
}

// ForbiddenResponse 返回禁止访问响应
func ForbiddenResponse(c *gin.Context, message string) {
	ErrorResponse(c, http.StatusForbidden, message)
}
