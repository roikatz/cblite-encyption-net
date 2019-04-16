using CBLEncryptionKeyGenerator.Repository;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web.Http;

namespace CBLEncryptionKeyGenerator.Controllers
{
    public class EncryptionKeyController : ApiController
    {

        EncryptionKeyRepository _repo;
        public EncryptionKeyController()
        {
            _repo = new EncryptionKeyRepository();
        }

        // GET: api/EncryptionKey/5
        public async Task<IHttpActionResult> Get(string id)
        {

            var encryptionKey = await _repo.GetEncryptionKey(id, 30);
            var key = new JObject()
                               {
                                { "key", new JValue(encryptionKey) }
                            };
            return Content(HttpStatusCode.OK, key);
        }
       
    }
}
