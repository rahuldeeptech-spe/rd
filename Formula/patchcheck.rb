class Patchcheck < Formula
  desc "Read-only checker for PHP2Shell, Node2Shell and other live runtime vulnerabilities"
  homepage "https://github.com/rahuldeeptech-spe/rd"
  url "https://github.com/rahuldeeptech-spe/rd/releases/download/v1.3.0/patchcheck-v1.3.0.tar.gz"
  sha256 "40417d8d4d958b014136e90b1e5f241f9c949f9d26c03aa3aa3b92f90cb9521e"
  license "MIT"

  def install
    libexec.install "patchcheck.sh", "advisories.tsv"
    (bin/"patchcheck").write <<~EOS
      #!/bin/bash
      exec /bin/bash "#{libexec}/patchcheck.sh" "$@"
    EOS
    doc.install "README.md", "CHANGELOG.md"
  end

  test do
    assert_match "patchcheck #{version}", shell_output("#{bin}/patchcheck --version")
  end
end
