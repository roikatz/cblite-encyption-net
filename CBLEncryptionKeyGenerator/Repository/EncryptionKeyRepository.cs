using CBLEncryptionKeyGenerator.Helpers;
using Couchbase;
using Couchbase.Authentication;
using Couchbase.Configuration.Client;
using Couchbase.IO;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace CBLEncryptionKeyGenerator.Repository
{
    public class EncryptionKeyRepository
    {

        const string bucket = "keys";

        public EncryptionKeyRepository()
        {
            var clientConfig = new ClientConfiguration
            {
                Servers = new List<Uri>
                {
                    new Uri("localhost:8091")
                },
              
            };

            var authenticator = new PasswordAuthenticator("keyUser", "password");
            ClusterHelper.Initialize(clientConfig, authenticator);
  
        }

        public async Task<string> GetEncryptionKey(string id, int ttlDays)
        {

            var expiration = TimeSpan.FromDays(ttlDays);
            var client = ClusterHelper.GetBucket(bucket);
            string generatedKey = string.Empty;

            var key = await client.GetAsync<string>($"key::{id}");
            if (key.Status == ResponseStatus.KeyNotFound)
            {

                string randomKey = GenerateRandomKey(id);
                var result = await client.InsertAsync($"key::{id}", randomKey, expiration);

                if (result.Success)
                    generatedKey = randomKey;
                else // the key was generated from a different server in the meantime
                {
                    result = await client.GetAsync<string>($" key::{id}");
                    generatedKey = result.Value;
                }

            }
            else
                if (key.Status != ResponseStatus.Success)
                throw new Exception($"Unable to reach Couchbase server {key.Status}, {key.Message}");
            return generatedKey;
        

        }

        private static string GenerateRandomKey(string id)
        {
            AES256Manager aes = new AES256Manager();
            var salt = aes.GenerateSalt();
            var phraseToEncrypt = Guid.NewGuid().ToString();

            var encrypted = aes.Encrypt(phraseToEncrypt, id, salt);
            return encrypted;
        }
    }
}