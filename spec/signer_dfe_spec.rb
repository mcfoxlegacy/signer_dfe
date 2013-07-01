# encoding: utf-8
require 'spec_helper'

describe SignerDfe::Signer do
  let(:xml_entrada) { "<?xml version=\"1.0\"?> <xml><ass Id=\"123456\"> <a> AAA </a><b>BBB</b>\n<c>CCCC</c>\n</ass>\n</xml>" }

  context "#to_xml" do
    it "instancia um objeto signer_dfe e retornar XML sem declaracao, espaçoes e carriage" do
      xml_saida = "<xml><ass Id=\"123456\"><a> AAA </a><b>BBB</b><c>CCCC</c></ass></xml>"
      OpenSSL::X509::Certificate.should_receive(:new);
      OpenSSL::PKey::RSA.should_receive(:new);
      signer_dfe = SignerDfe::Signer.new(xml_entrada, "afasdfa", "asdfasdf", "34343",'xml', 'ass' )
      signer_dfe.documento_xml.should_not be_nil

      signer_dfe.to_xml.should == xml_saida
    end
  end

  context "#root_node" do
    it "retorna o root_node pela tag_root" do
      doc = Nokogiri::XML(xml_entrada, &:noblanks)
      OpenSSL::X509::Certificate.should_receive(:new);
      OpenSSL::PKey::RSA.should_receive(:new);
      signer_dfe = SignerDfe::Signer.new(xml_entrada, "afasdfa", "asdfasdf", "34343",'xml', 'ass' )
      signer_dfe.root_node
      signer_dfe.root_node.should_not be_nil
      signer_dfe.root_node.to_s.should == doc.css("xml").first.to_s
    end

    it "retorna o root_node ja setado" do
      OpenSSL::X509::Certificate.should_receive(:new);
      OpenSSL::PKey::RSA.should_receive(:new);
      signer_dfe = SignerDfe::Signer.new(xml_entrada, "afasdfa", "asdfasdf", "34343",'xml', 'ass' )
      root_node_first = signer_dfe.root_node
      signer_dfe.root_node.should_not be_nil

      signer_dfe.tag_root = 'ass'
      signer_dfe.root_node

      signer_dfe.root_node.should == root_node_first
    end
  end

  context "#signature_node" do
    it "retorna a tag Signature encontrada no XML" do
      xml_entrada = "<?xml version=\"1.0\"?> <xml><ass Id=\"123456\"> <a> AAA </a><b>BBB</b>\n<c>CCCC</c>\n</ass><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><adafa>dsfa</adafa></Signature>\n</xml>"
      doc = Nokogiri::XML(xml_entrada, &:noblanks)
      node = doc.xpath('//xmlns:Signature', 'xmlns' => 'http://www.w3.org/2000/09/xmldsig#').first
      OpenSSL::X509::Certificate.should_receive(:new);
      OpenSSL::PKey::RSA.should_receive(:new);
      signer_dfe = SignerDfe::Signer.new(xml_entrada, "afasdfa", "asdfasdf", "34343",'xml', 'ass' )
      signature = signer_dfe.signature_node
      signature.should_not be_nil
      signature.to_s.should == node.to_s
    end

    it "retorna a tag Signature criada para o XML" do
      OpenSSL::X509::Certificate.should_receive(:new);
      OpenSSL::PKey::RSA.should_receive(:new);
      signer_dfe = SignerDfe::Signer.new(xml_entrada, "afasdfa", "asdfasdf", "34343",'xml', 'ass' )
      signature = signer_dfe.signature_node
      signature.should_not be_nil
      signature.to_s.should == "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"/>"
    end
  end

  context "#signed_info_node" do
    it "retorna a tag SignedInfo encontrada no XML" do
      xml_entrada = "<?xml version=\"1.0\"?> <xml><ass Id=\"123456\"> <a> AAA </a><b>BBB</b>\n<c>CCCC</c>\n</ass><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><adafa>dsfa</adafa></SignedInfo></Signature>\n</xml>"
      doc = Nokogiri::XML(xml_entrada, &:noblanks)
      node = doc.xpath('//xmlns:SignedInfo', 'xmlns' => 'http://www.w3.org/2000/09/xmldsig#').first
      OpenSSL::X509::Certificate.should_receive(:new);
      OpenSSL::PKey::RSA.should_receive(:new);
      signer_dfe = SignerDfe::Signer.new(xml_entrada, "afasdfa", "asdfasdf", "34343",'xml', 'ass' )
      signed_info = signer_dfe.signed_info_node
      signed_info.should_not be_nil
      signed_info.to_s.should == node.to_s
    end

    it "retorna a tag SignedInfo criada para o XML" do
      OpenSSL::X509::Certificate.should_receive(:new);
      OpenSSL::PKey::RSA.should_receive(:new);
      signer_dfe = SignerDfe::Signer.new(xml_entrada, "afasdfa", "asdfasdf", "34343",'xml', 'ass' )
      signed_info = signer_dfe.signed_info_node
      signed_info.should_not be_nil
      signed_info.serialize(save_with:Nokogiri::XML::Node::SaveOptions::NO_DECLARATION).sub("\n","").should == "<SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/></SignedInfo>"
    end
  end


  context "#x509_data_node" do
    it "retorna a tag x509Certificate gerado para o xml" do
      xml_entrada = "<?xml version=\"1.0\"?> <xml><ass Id=\"123456\"> <a> AAA </a><b>BBB</b>\n<c>CCCC</c>\n</ass><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><adafa>dsfa</adafa></SignedInfo></Signature>\n</xml>"
      cert = OpenSSL::X509::Certificate.new
      OpenSSL::X509::Certificate.should_receive(:new).and_return(cert);
      OpenSSL::PKey::RSA.should_receive(:new);
      cert.should_receive(:to_der)
      Base64.should_receive(:encode64).and_return('123456');
      signer_dfe = SignerDfe::Signer.new(xml_entrada, "afasdfa", "asdfasdf", "34343",'xml', 'ass' )
      x509certificate = signer_dfe.x509_data_node
      x509certificate.should_not be_nil
      x509certificate.serialize(save_with:Nokogiri::XML::Node::SaveOptions::NO_DECLARATION).sub("\n","").should == "<X509Data><X509Certificate>123456</X509Certificate></X509Data>"
    end
  end

  context "#digest!" do
    it "retorna o xml com a tag Reference com seus elementos" do
      cert = OpenSSL::X509::Certificate.new
      OpenSSL::X509::Certificate.should_receive(:new).and_return(cert);
      OpenSSL::PKey::RSA.should_receive(:new);
      Base64.should_receive(:encode64).and_return('123456');
      signer_dfe = SignerDfe::Signer.new(xml_entrada, "afasdfa", "asdfasdf", "34343",'xml', 'ass' )
      signer_dfe = signer_dfe.digest!
      signer_dfe.should_not be_nil
      xml = "<xml><ass Id=\"123456\"><a> AAA </a><b>BBB</b><c>CCCC</c></ass><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><Reference URI=\"#123456\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><Transform Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>123456</DigestValue></Reference></SignedInfo></Signature></xml>"
      signer_dfe.documento_xml.serialize(save_with:Nokogiri::XML::Node::SaveOptions::NO_DECLARATION).sub("\n","").should == xml
    end
  end

  context "#sign!" do
    it "retorna o xml com assinatura" do
      cert = OpenSSL::X509::Certificate.new
      key = OpenSSL::PKey::RSA.new
      OpenSSL::X509::Certificate.should_receive(:new).and_return(cert);
      OpenSSL::PKey::RSA.should_receive(:new).and_return(key);
      cert.should_receive(:to_der)
      key.should_receive(:sign).and_return("1234567890")
      Base64.should_receive(:encode64).any_number_of_times.and_return('123456');
      signer_dfe = SignerDfe::Signer.new(xml_entrada, "afasdfa", "asdfasdf", "34343",'xml', 'ass' )
      signer_dfe.sign!
      p signer_dfe.to_xml
      signer_dfe.to_xml.should == "<xml><ass Id=\"123456\"><a> AAA </a><b>BBB</b><c>CCCC</c></ass><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><Reference URI=\"#123456\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><Transform Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>123456</DigestValue></Reference></SignedInfo><SignatureValue>123456</SignatureValue><KeyInfo><X509Data><X509Certificate>123456</X509Certificate></X509Data></KeyInfo></Signature></xml>"
    end

  end

end