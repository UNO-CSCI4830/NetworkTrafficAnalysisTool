def generate_connection_summary(connection):
    process = connection.get("process_name", "Unknown process")
    remote_ip = connection.get("remote_ip", "unknown IP")
    remote_port = connection.get("remote_port", "unknown port")
    label = connection.get("label", "LOW")
    score = connection.get("score", 0)

    return (
        f"{process} connected to {remote_ip} on port {remote_port}. "
        f"The connection has a risk level of {label} with a score of {score}."
    )


def summarize_data(sent_bytes, received_bytes):
    total_bytes = sent_bytes + received_bytes

    return (
        f"Data sent: {sent_bytes} bytes. "
        f"Data received: {received_bytes} bytes. "
        f"Total data transferred: {total_bytes} bytes."
    )