// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.AspNetCore.Mvc;

namespace ReverseProxy.Tunnel.API.Controllers
{
    /// <summary>
    /// Sample controller.
    /// </summary>
    [ApiController]
    public class HttpController : ControllerBase
    {
        /// <summary>
        /// Returns a 200 response.
        /// </summary>
        [HttpGet]
        [Route("/api/noop")]
        public void NoOp()
        {
        }

        /// <summary>
        /// Returns a 200 response dumping all info from the incoming request.
        /// </summary>
        [HttpGet, HttpPost]
        [Route("/api/dump")]
        [Route("/{**catchall}", Order = int.MaxValue)] // Make this the default route if nothing matches
        public async Task<IActionResult> Dump()
        {
            var result = await HttpRequestDump.GetDumpAsync(HttpContext, Request, true);
            return Ok(result);
        }

        /// <summary>
        /// Returns a 200 response dumping all info from the incoming request.
        /// </summary>
        [HttpGet]
        [Route("/api/statuscode")]
        public void Status(int statusCode)
        {
            Response.StatusCode = statusCode;
        }

        /// <summary>
        /// Returns a 200 response dumping all info from the incoming request.
        /// </summary>
        [HttpGet]
        [Route("/api/headers")]
        public void Headers([FromBody] Dictionary<string, string> headers)
        {
            foreach (var (key, value) in headers)
            {
                Response.Headers[key] = value;
            }
        }
    }
}
