# encoding: utf-8
require "nokogiri"
require "base64"
require "digest/sha1"
require "openssl"

require "signer_dfe/version"

def signer_xml(documento_xml, certificado_pem, private_key_pem, senha, tag_root, tag_assinada)
  signer = SignerDfe::Signer.new(documento_xml, certificado_pem, private_key_pem, senha, tag_root, tag_assinada)
  signer.sign!
  signer.to_xml
end


def get_informations_certificado(certificado_pem)
  inf_certificate = SignerDfe::InformationCertificate.new(certificado_pem)
  inf_certificate.get_informations
end

module SignerDfe

  class Signer
    attr_accessor :documento_xml, :certificado_pem, :private_key_pem, :tag_root, :tag_assinada
    attr_writer :root_node


    def initialize(documento_xml, certificado_pem, private_key_pem, senha, tag_root, tag_assinada)
      self.documento_xml = Nokogiri::XML(documento_xml.to_s, &:noblanks)
      self.certificado_pem = OpenSSL::X509::Certificate.new(certificado_pem)
      self.private_key_pem = OpenSSL::PKey::RSA.new(private_key_pem, senha)
      self.tag_root = tag_root
      self.tag_assinada = tag_assinada
    end

    def to_xml
      documento_xml.serialize(save_with:Nokogiri::XML::Node::SaveOptions::NO_DECLARATION).sub("\n","")
    end

    def root_node
      @root_node ||= documento_xml.css(tag_root).first
    end

    def canonicalize(node = documento_xml)
      node.canonicalize(Nokogiri::XML::XML_C14N_1_1)
    end

    # <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    def signature_node
      node = documento_xml.xpath('//xmlns:Signature', 'xmlns' => 'http://www.w3.org/2000/09/xmldsig#').first
      unless node
        node = add_nodes(root_node, 'Signature', nil, 'http://www.w3.org/2000/09/xmldsig#')
      end
      node
    end

    # <SignedInfo>
    #   <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    #   <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
    #   ...
    # </SignedInfo>
    def signed_info_node
      node = signature_node.xpath('//xmlns:SignedInfo', 'xmlns' => 'http://www.w3.org/2000/09/xmldsig#').first
      unless node
        node = Nokogiri::XML::Node.new('SignedInfo', documento_xml)
        signature_node.add_child(node)

        add_nodes_with_attributes(node, 'CanonicalizationMethod', 'Algorithm', 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315')

        add_nodes_with_attributes(node, 'SignatureMethod', 'Algorithm', 'http://www.w3.org/2000/09/xmldsig#rsa-sha1')
      end
      node
    end

    # <KeyInfo>
    #   <X509Data>
    #     <X509Certificate>MIID+jCCAuKgAwIBAgIEAMdxxTANBgkqhkiG9w0BAQUFADBsMQswCQYDVQQGEwJTRTEeMBwGA1UEChMVTm9yZGVhIEJhbmsgQUIgKHB1YmwpMScwJQYDVQQDEx5Ob3JkZWEgcm9sZS1jZXJ0aWZpY2F0ZXMgQ0EgMDExFDASBgNVBAUTCzUxNjQwNi0wMTIwMB4XDTA5MDYxMTEyNTAxOVoXDTExMDYxMTEyNTAxOVowcjELMAkGA1UEBhMCU0UxIDAeBgNVBAMMF05vcmRlYSBEZW1vIENlcnRpZmljYXRlMRQwEgYDVQQEDAtDZXJ0aWZpY2F0ZTEUMBIGA1UEKgwLTm9yZGVhIERlbW8xFTATBgNVBAUTDDAwOTU1NzI0Mzc3MjCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAwcgz5AzbxTbsCE51No7fPnSqmQBIMW9OiPkiHotwYQTl+H9qwDvQRyBqHN26tnw7hNvEShd1ZRGUg4drMEXDV5CmKqsAevs9lauWDaHnGKPNHZJ1hNNYXHwymksEz5zMnG8eqRdhb4vOV2FzreJeYpsgx31Bv0aTofHcHVz4uGcCAwEAAaOCASAwggEcMAkGA1UdEwQCMAAwEQYDVR0OBAoECEj6Y9/vU03WMBMGA1UdIAQMMAowCAYGKoVwRwEDMBMGA1UdIwQMMAqACEIFjfLBeTpRMDcGCCsGAQUFBwEBBCswKTAnBggrBgEFBQcwAYYbaHR0cDovL29jc3Aubm9yZGVhLnNlL1JDQTAxMA4GA1UdDwEB/wQEAwIGQDCBiAYDVR0fBIGAMH4wfKB6oHiGdmxkYXA6Ly9sZGFwLm5iLnNlL2NuPU5vcmRlYSUyMHJvbGUtY2VydGlmaWNhdGVzJTIwQ0ElMjAwMSxvPU5vcmRlYSUyMEJhbmslMjBBQiUyMChwdWJsKSxjPVNFP2NlcnRpZmljYXRlcmV2b2NhdGlvbmxpc3QwDQYJKoZIhvcNAQEFBQADggEBAEXUv87VpHk51y3TqkMb1MYDqeKvQRE1cNcvhEJhIzdDpXMA9fG0KqvSTT1e0ZI2r78mXDvtTZnpic44jX2XMSmKO6n+1taAXq940tJUhF4arYMUxwDKOso0Doanogug496gipqMlpLgvIhGt06sWjNrvHzp2eGydUFdCsLr2ULqbDcut7g6eMcmrsnrOntjEU/J3hO8gyCeldJ+fI81qarrK/I0MZLR5LWCyVG/SKduoxHLX7JohsbIGyK1qAh9fi8l6X1Rcu80v5inpu71E/DnjbkAZBo7vsj78zzdk7KNliBIqBcIszdJ3dEHRWSI7FspRxyiR0NDm4lpyLwFtfw=</X509Certificate>
    #   </X509Data>
    # </KeyInfo>
    def x509_data_node

      cetificate_node = Nokogiri::XML::Node.new('X509Certificate', documento_xml)
      cetificate_node.content = Base64.encode64(certificado_pem.to_der).gsub("\n", '')

      data_node = Nokogiri::XML::Node.new('X509Data', documento_xml)
      data_node.add_child(cetificate_node)

      key_info_node = Nokogiri::XML::Node.new('KeyInfo', documento_xml)
      key_info_node.add_child(data_node)

      signed_info_node.add_next_sibling(key_info_node)

      data_node
    end

    # <Reference URI="#_0">
    #   <Transforms>
    #     <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    #   </Transforms>
    #   <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
    #   <DigestValue>aeqXriJuUCk4tPNPAGDXGqHj6ao=</DigestValue>
    # </Reference>
    def digest!
      target_node = documento_xml.css(tag_assinada).first
      id = target_node.attribute('Id')

      target_canon = canonicalize(target_node)
      target_digest = Base64.encode64(OpenSSL::Digest::SHA1.digest(target_canon)).strip

      add_nodes_transforms(id, target_digest)
      self
    end

    def add_nodes_transforms(id, target_digest)

      reference_node = add_nodes_with_attributes(signed_info_node, 'Reference', 'URI', (id.text.size > 0 ? "##{id.text}" : "") )

      transforms_node = add_nodes(reference_node, 'Transforms')

      add_nodes_with_attributes(transforms_node, 'Transform', 'Algorithm', 'http://www.w3.org/2000/09/xmldsig#enveloped-signature')

      add_nodes_with_attributes(transforms_node, 'Transform', 'Algorithm', 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315')

      add_nodes_with_attributes(reference_node, 'DigestMethod', 'Algorithm', 'http://www.w3.org/2000/09/xmldsig#sha1')

      add_nodes(reference_node, 'DigestValue', target_digest)

    end

    # <SignatureValue>...</SignatureValue>
    def sign!
      digest!

      x509_data_node

      signed_info_canon = canonicalize(signed_info_node)

      signature = private_key_pem.sign(OpenSSL::Digest::SHA1.new, signed_info_canon)
      signature_value_digest = Base64.encode64(signature).gsub("\n", '')

      signature_value_node = Nokogiri::XML::Node.new('SignatureValue', documento_xml)
      signature_value_node.content = signature_value_digest
      signed_info_node.add_next_sibling(signature_value_node)
      self
    end

    private
      def add_nodes(node_pai, nome_node, conteudo = nil, namespace = nil)
        node = Nokogiri::XML::Node.new(nome_node, documento_xml)
        node.content = conteudo unless conteudo.nil?
        node.default_namespace = namespace unless namespace.nil?
        node_pai.add_child(node)
        node
      end

      def add_nodes_with_attributes(node_pai, nome_node, nome_atributo, valor_atributo)
        node = Nokogiri::XML::Node.new(nome_node, documento_xml)
        node[nome_atributo] = valor_atributo
        node_pai.add_child(node)
        node
      end

  end

  class InformationCertificate
    SUBJECTALTNAME = 'subjectAltName'
    IDENTIFICADOR_CNPJ = '2.16.76.1.3.3'
    attr_accessor :certificado_pem

    def initialize(certificado)
      self.certificado_pem = OpenSSL::X509::Certificate.new(certificado)
    end

    #{:validade => DD-MM-YYYY HH:mm:ss, :cnpj => 'XXXXXXXXXXXXXX' }
    def get_informations
      hash = {}
      hash[:validade] = certificado_pem.not_after
      extensions = self.certificado_pem.extensions
      extensions.each do |extension|
        if extension.oid == SUBJECTALTNAME
           cnpj = extract_cnpj(extension.to_der)
           hash[:cnpj] = cnpj unless cnpj.empty?
        end
      end
      hash
    end

    private
      def extract_cnpj(extension_der)
        alternative_names = find_alternative_names(extension_der)
        alternative_names.each do |alternative_name|
          if alternative_name.value.instance_of?(Array)
            asn1_data = alternative_name.value
            if asn1_data[0].instance_of?(OpenSSL::ASN1::ObjectId)
              if asn1_data[0].value == IDENTIFICADOR_CNPJ
                return asn1_data[1].value[0].value
              end
            end
          end
        end
      end

      def find_alternative_names(extension_der)
        sequence = OpenSSL::ASN1.decode(extension_der).value[1].value
        OpenSSL::ASN1.decode(sequence).value
      end

  end

end
