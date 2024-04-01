// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;

using Microsoft.Extensions.DependencyInjection;

namespace Yarp.ReverseProxy.Forwarder;

public class ForwarderHttpClientFactorySelector
    : IForwarderHttpClientFactorySelector
{
    public static ForwarderHttpClientFactorySelector Create(IServiceProvider serviceProvider)
    {
        var forwarderHttpClientFactories = serviceProvider.GetServices<IForwarderHttpClientFactorySelective>();
        if (forwarderHttpClientFactories.Count()==0)
        {
            // TODO: Exception and log
            throw new Exception("no factories");
        }
        return new ForwarderHttpClientFactorySelector(forwarderHttpClientFactories);
    }

    private readonly IForwarderHttpClientFactorySelective[] _forwarderHttpClientFactories;

    public ForwarderHttpClientFactorySelector(
        IEnumerable<IForwarderHttpClientFactorySelective> forwarderHttpClientFactories)
    {
        _forwarderHttpClientFactories = forwarderHttpClientFactories.ToArray();
    }

    public HttpMessageInvoker CreateClient(ForwarderHttpClientContext context)
    {
        IForwarderHttpClientFactorySelective? found = null;
        foreach (var item in _forwarderHttpClientFactories)
        {
            if (item.CanHandle(context))
            {
                if (found is null)
                {
                    found = item;
                }
                else
                {
                    throw new Exception("multiple matches");
                }
            }
        }
        if (found is null)
        {
            throw new ArgumentException("no match");
        }
        else
        {
            return found.CreateClient(context);
        }
    }
}
