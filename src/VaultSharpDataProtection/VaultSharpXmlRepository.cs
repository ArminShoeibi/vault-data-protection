using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.Repositories;
using VaultSharp;
using VaultSharp.Core;

namespace VaultSharpDataProtection;

/// <summary>
/// Provides an <see cref="IXmlRepository"/> implementation for storing
/// data protection keys in Vault using the VaultSharp client.
/// </summary>
/// <seealso cref="Microsoft.AspNetCore.DataProtection.Repositories.IXmlRepository" />
public class VaultSharpXmlRepository : IDeletableXmlRepository
{
    private static readonly TaskFactory _factory =
        new TaskFactory(
            CancellationToken.None,
            TaskCreationOptions.None,
            TaskContinuationOptions.None,
            TaskScheduler.Default);

    private readonly IVaultClient _vault;
    private readonly string _path;
    private readonly string _mountPoint;

    /// <summary>
    /// Initializes a new instance of the <see cref="VaultSharpXmlRepository"/> class.
    /// </summary>
    /// <param name="vault">The vault client to use.</param>
    /// <param name="path">The path store keys under.</param>
    /// <param name="mountPoint">The Vault key/value mount point.</param>
    public VaultSharpXmlRepository(IVaultClient vault, string path, string mountPoint)
    {
        _vault = vault;
        _path = path;
        _mountPoint = mountPoint;
    }


    /// <inheritdoc/>
    public IReadOnlyCollection<XElement> GetAllElements()
    {
        try
        {
            var response = RunSync(async () => await _vault.V1.Secrets.KeyValue.V2.ReadSecretAsync(_path, null, _mountPoint));
            return response.Data.Data.Values.Select(e => e switch
            {
                string v => XElement.Parse(v),
                JsonElement { ValueKind: JsonValueKind.String } j when j.GetString() is { } s => XElement.Parse(s),
                _ => throw new InvalidCastException($"Expected JSON string, but got {e.GetType()}.")
            }).ToList()
              .AsReadOnly();
        }
        catch (VaultApiException e) when (e.StatusCode == 404)
        {
            return Array.Empty<XElement>();
        }
    }

    /// <inheritdoc/>
    public void StoreElement(XElement element, string friendlyName)
    {
        RunSync(async () =>
        {
            int? version;
            IDictionary<string, object> value;
            try
            {
                var response = await _vault.V1.Secrets.KeyValue.V2.ReadSecretAsync(_path, null, _mountPoint);
                version = response.Data.Metadata.Version;
                value = response.Data.Data;
            }
            catch (VaultApiException e) when (e.StatusCode == 404)
            {
                version = null;
                value = new Dictionary<string, object>();
            }

            value[friendlyName] = element.ToString(SaveOptions.DisableFormatting);

            await _vault.V1.Secrets.KeyValue.V2.WriteSecretAsync(_path, value, version, _mountPoint);
        });
    }

    private static T RunSync<T>(Func<Task<T>> method)
    {
        return _factory.StartNew(method)
            .Unwrap()
            .GetAwaiter()
            .GetResult();
    }

    private static void RunSync(Func<Task> method)
    {
        _factory.StartNew(method)
            .Unwrap()
            .GetAwaiter()
            .GetResult();
    }

    /// <inheritdoc/>
    public bool DeleteElements(Action<IReadOnlyCollection<IDeletableElement>> chooseElements)
    {
        ArgumentNullException.ThrowIfNull(chooseElements);
        try
        {
            return RunSync<bool>(async () =>
            {
                var response = await _vault.V1.Secrets.KeyValue.V2.ReadSecretAsync(_path, null, _mountPoint);
                int? version = response.Data.Metadata.Version;
                IDictionary<string, object> value = response.Data.Data;

                if (value.Count < 1 || version is null)
                {
                    return false;
                }

                var deletableElements = value.Select(kv =>
                {
                    var element = kv.Value switch
                    {
                        string v => XElement.Parse(v),
                        JsonElement { ValueKind: JsonValueKind.String } j when j.GetString() is { } s => XElement.Parse(s),
                        _ => throw new InvalidCastException($"Expected JSON string, but got {kv.Value.GetType()}.")
                    };
                    var id = element.Attribute("id")?.Value;
                    if (string.IsNullOrWhiteSpace(id) || id.Equals(kv.Key, StringComparison.OrdinalIgnoreCase) is false)
                    {
                        throw new InvalidOperationException("Element is missing the 'id' attribute.");
                    }
                    return new DeletableElement(kv.Key, element);
                }).ToList();

                chooseElements(deletableElements);

                var elementsToDelete = deletableElements.Where(e => e.DeletionOrder.HasValue)
                                                        .OrderBy(e => e.DeletionOrder.GetValueOrDefault())
                                                        .ToList();

                if (elementsToDelete is null || elementsToDelete.Count < 1)
                {
                    return false;
                }

                foreach (var element in elementsToDelete)
                {
                    value.Remove(element.Key);
                }

                await _vault.V1.Secrets.KeyValue.V2.WriteSecretAsync(_path, value, version, _mountPoint);
                // TODO: check  the write is successful then delete the old(current) version
                await _vault.V1.Secrets.KeyValue.V2.DeleteSecretVersionsAsync(_path, versions: [version.GetValueOrDefault()], _mountPoint);
                return true;
            });
        }
        catch
        {
            return false;
        }
    }

    private sealed class DeletableElement : IDeletableElement
    {
        public DeletableElement(string key, XElement element)
        {
            Key = key;
            Element = element;
        }
        public XElement Element { get; }
        public int? DeletionOrder { get; set; }
        public string Key { get; }
    }
}
