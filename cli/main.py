import os
import sys
import time
from pathlib import Path
from typing import Optional, List, Dict, Any
import typer
from rich.console import Console
from rich.progress import Progress, TextColumn, BarColumn, TimeElapsedColumn, SpinnerColumn
from rich.panel import Panel
from rich.table import Table
from rich import print as rprint
from rich.markdown import Markdown

# Add the parent directory to the path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from sentinelmind.core.ingestor import LogIngestor
from sentinelmind.core.parser import LogParser
from sentinelmind.core.feature_extractor import FeatureExtractor
from sentinelmind.core.anomaly_detector import AnomalyDetector
from sentinelmind.core.attack_linker import AttackLinker
from sentinelmind.core.storage import StorageHandler
from sentinelmind.core.trainer import ModelTrainer
from sentinelmind.utils.logger import get_logger
from sentinelmind.utils.config import get_config

# Initialize
app = typer.Typer(
    help="SentinelMind: AI-Powered Threat Hunting Engine",
    add_completion=False
)
console = Console()
logger = get_logger()
config = get_config()


@app.command("scan")
def scan_logs(
    file_path: str = typer.Argument(..., help="Path to the log file to scan"),
    model_type: str = typer.Option("isolation_forest", help="ML model to use (isolation_forest or autoencoder)"),
    threshold: Optional[float] = typer.Option(None, help="Override anomaly detection threshold (0.0 to 1.0)"),
    export_path: Optional[str] = typer.Option(None, help="Path to export results (optional)"),
    export_format: str = typer.Option("json", help="Export format (json or csv)")
):
    """Scan log files for security anomalies and potential threats."""
    
    with console.status("[bold green]Initializing scan...", spinner="dots") as status:
        # Initialize components
        ingestor = LogIngestor()
        parser = LogParser()
        feature_extractor = FeatureExtractor()
        storage = StorageHandler()
        
        # Initialize the anomaly detector with the specified model
        detector = AnomalyDetector(model_type=model_type, load_model=True)
        if threshold is not None:
            detector.threshold = max(0.0, min(threshold, 1.0))
        
        # Initialize attack linker
        attack_linker = AttackLinker()
        
        status.update(f"[bold green]Ingesting log file: {file_path}")
    
    # Ingest the log file
    try:
        logs, metadata = ingestor.ingest_file(file_path)
    except Exception as e:
        console.print(f"[bold red]Error ingesting log file:[/bold red] {str(e)}")
        return
    
    # Register the log file in storage
    try:
        log_file_id = storage.register_log_file(
            filename=metadata['filename'],
            file_path=metadata['file_path'],
            log_type=metadata['log_type'],
            records_count=metadata['records_count'],
            file_hash=metadata.get('file_hash'),
            file_size=metadata.get('file_size')
        )
    except Exception as e:
        console.print(f"[bold red]Error registering log file:[/bold red] {str(e)}")
        return
    
    # Parse logs
    with console.status(f"[bold green]Parsing {len(logs)} log entries...", spinner="dots") as status:
        normalized_logs = parser.parse_logs(logs)
    
    # Process logs in batches with progress bar
    anomaly_count = 0
    all_anomalies = []
    batch_size = 1000
    
    total_batches = (len(normalized_logs) + batch_size - 1) // batch_size
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold green]{task.description}"),
        BarColumn(),
        TextColumn("[bold]{task.completed}/{task.total}"),
        TimeElapsedColumn()
    ) as progress:
        scan_task = progress.add_task("[bold green]Analyzing logs for anomalies...", total=total_batches)
        
        for i in range(0, len(normalized_logs), batch_size):
            batch = normalized_logs[i:i+batch_size]
            
            # Extract features
            features_df, _ = feature_extractor.extract_features(batch)
            
            if not features_df.empty:
                # Predict anomalies
                predictions, scores = detector.predict(features_df)
                
                # Store anomalies
                for j, (pred, score) in enumerate(zip(predictions, scores)):
                    if pred == 1:  # If it's an anomaly
                        anomaly_count += 1
                        
                        # Get the log entry
                        log_entry = batch[j]
                        
                        # Store the anomaly
                        try:
                            anomaly_id = storage.store_anomaly(
                                log_file_id=log_file_id,
                                timestamp=log_entry.get('timestamp', ''),
                                event_data=log_entry,
                                score=float(score),
                                detection_algorithm=model_type
                            )
                            
                            # Add ID to the log entry for linking
                            log_entry['id'] = anomaly_id
                            log_entry['score'] = float(score)
                            log_entry['severity'] = min(max(float(score), 0), 1)
                            
                            # Add to list of anomalies
                            all_anomalies.append(log_entry)
                            
                        except Exception as e:
                            logger.error(f"Error storing anomaly: {str(e)}")
            
            # Update progress
            progress.update(scan_task, advance=1)
    
    # Link anomalies into attack chains
    with console.status("[bold green]Correlating anomalies into attack chains...", spinner="dots"):
        attack_chains = attack_linker.cluster_anomalies(all_anomalies)
        
        # Store attack chains
        for chain in attack_chains:
            try:
                chain_id = storage.store_attack_chain(
                    name=chain['name'],
                    anomaly_ids=chain['anomaly_ids'],
                    start_time=chain['start_time'],
                    end_time=chain['end_time'],
                    severity=chain['severity'],
                    confidence=chain['confidence'],
                    mitre_techniques=chain['mitre_techniques']
                )
            except Exception as e:
                logger.error(f"Error storing attack chain: {str(e)}")
    
    # Display results
    console.print()
    console.print(Panel(f"[bold green]Scan Complete: {file_path}[/bold green]", border_style="green"))
    console.print()
    
    # Get stats
    stats = storage.get_stats()
    
    # Create summary table
    table = Table(title="Scan Results")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Log file", metadata['filename'])
    table.add_row("Log type", metadata['log_type'])
    table.add_row("Records processed", str(metadata['records_count']))
    table.add_row("Anomalies detected", str(anomaly_count))
    table.add_row("Attack chains identified", str(len(attack_chains)))
    
    if anomaly_count > 0:
        table.add_row("Detection threshold", f"{detector.threshold:.2f}")
    
    console.print(table)
    
    # Display attack chains if any were found
    if attack_chains:
        console.print()
        chain_table = Table(title="Potential Attack Chains")
        chain_table.add_column("ID", style="cyan")
        chain_table.add_column("Name", style="green")
        chain_table.add_column("Severity", style="red")
        chain_table.add_column("Confidence", style="yellow")
        chain_table.add_column("Anomalies", style="blue")
        chain_table.add_column("Techniques", style="magenta")
        
        for i, chain in enumerate(attack_chains, 1):
            severity_str = f"{chain['severity']:.2f}"
            confidence_str = f"{chain['confidence']:.2f}"
            techniques_str = ", ".join(chain['mitre_techniques']) if chain['mitre_techniques'] else "Unknown"
            
            chain_table.add_row(
                str(i),
                chain['name'],
                severity_str,
                confidence_str,
                str(len(chain['anomaly_ids'])),
                techniques_str
            )
        
        console.print(chain_table)
    
    # Export results if requested
    if export_path:
        try:
            output_path = storage.export_findings(
                output_path=export_path,
                export_format=export_format,
                include_chains=True,
                include_anomalies=True
            )
            console.print(f"[bold green]Results exported to:[/bold green] {output_path}")
        except Exception as e:
            console.print(f"[bold red]Error exporting results:[/bold red] {str(e)}")


@app.command("train")
def train_model(
    data_path: str = typer.Argument(..., help="Path to log file or directory for training"),
    model_type: str = typer.Option("isolation_forest", help="Model type (isolation_forest or autoencoder)"),
    recursive: bool = typer.Option(True, help="Recursively process directories"),
    force: bool = typer.Option(False, help="Force retraining even if a model exists")
):
    """Train or update anomaly detection models with new log data."""
    
    console.print(Panel(f"[bold blue]Training {model_type} model from {data_path}[/bold blue]", border_style="blue"))
    
    # Check if path exists
    if not os.path.exists(data_path):
        console.print(f"[bold red]Error:[/bold red] Path {data_path} does not exist.")
        return
    
    # Initialize trainer
    trainer = ModelTrainer(model_type=model_type)
    
    # Check if we should train or if a model exists
    model_path = os.path.join(config.get("models_dir", "models"), f"{model_type}_model.pkl")
    if os.path.exists(model_path) and not force:
        if not typer.confirm("Model already exists. Do you want to retrain it?"):
            console.print("[yellow]Training cancelled.[/yellow]")
            return
    
    with console.status("[bold green]Training model...", spinner="dots") as status:
        # Train based on file or directory
        if os.path.isfile(data_path):
            status.update(f"[bold green]Training from file: {data_path}")
            metadata = trainer.train_from_file(data_path)
        else:
            status.update(f"[bold green]Training from directory: {data_path}")
            metadata = trainer.train_from_directory(data_path, recursive=recursive)
    
    # Display results
    console.print()
    
    if metadata.get('success', False):
        console.print(Panel("[bold green]Training Completed Successfully[/bold green]", border_style="green"))
        
        # Create summary table
        table = Table(title="Training Results")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Model type", metadata['model_type'])
        table.add_row("Files processed", str(metadata['files_processed']))
        table.add_row("Logs processed", str(metadata['logs_processed']))
        table.add_row("Features extracted", str(metadata['features_extracted']))
        
        if 'file_types' in metadata:
            table.add_row("File types", ", ".join(metadata['file_types']))
        
        if 'started_at' in metadata and 'completed_at' in metadata:
            try:
                start = datetime.fromisoformat(metadata['started_at'])
                end = datetime.fromisoformat(metadata['completed_at'])
                duration = (end - start).total_seconds()
                table.add_row("Training duration", f"{duration:.2f} seconds")
            except:
                pass
        
        console.print(table)
        console.print(f"[bold green]Model saved to:[/bold green] {model_path}")
        
    else:
        console.print(Panel("[bold red]Training Failed[/bold red]", border_style="red"))
        
        if 'errors' in metadata and metadata['errors']:
            console.print("[bold red]Errors:[/bold red]")
            for error in metadata['errors']:
                console.print(f"- {error}")


@app.command("export")
def export_data(
    output_path: str = typer.Argument(..., help="Path to export findings"),
    format: str = typer.Option("json", help="Export format (json or csv)"),
    include_chains: bool = typer.Option(True, help="Include attack chains"),
    include_anomalies: bool = typer.Option(True, help="Include individual anomalies"),
    limit: int = typer.Option(1000, help="Maximum number of records to export")
):
    """Export threat findings to JSON or CSV format."""
    
    console.print(Panel(f"[bold blue]Exporting findings to {output_path}[/bold blue]", border_style="blue"))
    
    try:
        # Initialize storage handler
        storage = StorageHandler()
        
        # Export findings
        with console.status("[bold green]Exporting data...", spinner="dots"):
            output_file = storage.export_findings(
                output_path=output_path,
                export_format=format,
                include_chains=include_chains,
                include_anomalies=include_anomalies
            )
        
        console.print(f"[bold green]Data exported successfully to:[/bold green] {output_file}")
        
        # Show stats
        stats = storage.get_stats()
        
        table = Table(title="Export Statistics")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        if include_anomalies:
            table.add_row("Anomalies exported", str(min(stats.get('anomalies_count', 0), limit)))
        
        if include_chains:
            table.add_row("Attack chains exported", str(min(stats.get('attack_chains_count', 0), limit)))
        
        console.print(table)
        
    except Exception as e:
        console.print(f"[bold red]Error exporting data:[/bold red] {str(e)}")


@app.command("info")
def show_info():
    """Show information about SentinelMind configuration and status."""
    
    console.print(Panel("[bold blue]SentinelMind: AI-Powered Threat Hunting Engine[/bold blue]", border_style="blue"))
    
    # Get configuration
    config_data = config.config
    
    # Get model information
    model_dir = config.get("models_dir", "models")
    models_available = []
    
    if os.path.exists(model_dir):
        for file in os.listdir(model_dir):
            if file.endswith("_model.pkl"):
                model_name = file.replace("_model.pkl", "")
                models_available.append(model_name)
    
    # Get database stats
    try:
        storage = StorageHandler()
        stats = storage.get_stats()
    except:
        stats = {}
    
    # Display configuration
    console.print("[bold cyan]Configuration:[/bold cyan]")
    
    config_table = Table(show_header=False)
    config_table.add_column("Setting", style="green")
    config_table.add_column("Value", style="yellow")
    
    for key, value in {
        "Database File": config.get("db_file"),
        "Models Directory": config.get("models_dir"),
        "Anomaly Threshold": config.get("anomaly_threshold"),
        "Attack Chain Time Window": f"{config.get('attack_chain_time_window')} seconds",
        "Max Threads": config.get("max_threads")
    }.items():
        config_table.add_row(key, str(value))
    
    console.print(config_table)
    
    # Display available models
    console.print("\n[bold cyan]Available Models:[/bold cyan]")
    
    if models_available:
        models_table = Table(show_header=False)
        models_table.add_column("Model", style="green")
        models_table.add_column("Status", style="yellow")
        
        for model in models_available:
            models_table.add_row(model, "Available")
        
        console.print(models_table)
    else:
        console.print("[yellow]No trained models available. Run 'train' command to create models.[/yellow]")
    
    # Display database stats
    console.print("\n[bold cyan]Database Statistics:[/bold cyan]")
    
    if stats:
        stats_table = Table(show_header=False)
        stats_table.add_column("Statistic", style="green")
        stats_table.add_column("Value", style="yellow")
        
        for key, value in {
            "Log Files Processed": stats.get("log_files_count", 0),
            "Anomalies Detected": stats.get("anomalies_count", 0),
            "Attack Chains Identified": stats.get("attack_chains_count", 0),
            "High Severity Anomalies": stats.get("high_severity_anomalies", 0),
            "Average Anomaly Severity": f"{stats.get('avg_anomaly_severity', 0):.2f}",
            "Last Scan Time": stats.get("last_scan_time", "Never")
        }.items():
            stats_table.add_row(key, str(value))
        
        console.print(stats_table)
    else:
        console.print("[yellow]No database statistics available yet.[/yellow]")


def main():
    """Main entry point for the CLI."""
    app()


if __name__ == "__main__":
    main() 